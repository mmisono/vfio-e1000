#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <linux/vfio.h>

#include "e1000.h"

#define ASSERT(expr, msg, ...)                                             \
    do {                                                                   \
        if (!(expr)) {                                                     \
            fprintf(stderr, "[Error] %s:%3d %15s(): ", __FILE__, __LINE__, \
                    __func__);                                             \
            fprintf(stderr, msg "\n", ##__VA_ARGS__);                      \
            exit(1);                                                       \
        }                                                                  \
    } while (0)

#ifndef NDEBUG
#define DASSERT ASSERT
#define debug(msg, ...)                                                        \
    do {                                                                       \
        fprintf(stderr, "[Debug] %s:%d %s(): ", __FILE__, __LINE__, __func__); \
        fprintf(stderr, msg "\n", ##__VA_ARGS__);                              \
    } while (0)
#else
#define DASSERT(...) \
    do {             \
    } while (0)
#define debug(fmt, ...) \
    do {                \
    } while (0)
#endif

struct device {
    struct rdesc* rx_ring;
    struct tdesc* tx_ring;
    void** rx_ring_buf_vaddr;
    void** tx_ring_buf_vaddr;
    int fd;                         // VFIO device fd
    int gfd;                        // VFIO group fd
    int cfd;                        // VFIO container fd
    int efd;                        // event fd (for INTx, MSI)
    int efds[MAX_MSIX_VECTOR_NUM];  // event fd (for MSI-x)
    int epfd;                       // epoll fd
    struct vfio_device_info device_info;
    struct vfio_group_status group_status;
    struct vfio_iommu_type1_info iommu_info;
    struct vfio_region_info regs[VFIO_PCI_NUM_REGIONS];
    struct vfio_irq_info irqs[VFIO_PCI_NUM_IRQS];
    void* mmio_addr;  // mmio address (BAR0);
};

#define BUFSIZE 4096
#define NUM_OF_DESC 256  // 256 * 16 = 4096

static char* region_name[VFIO_PCI_NUM_REGIONS] = {
    "BAR0", "BAR1", "BAR2", "BAR3", "BAR4", "BAR5", "ROM", "CONFIG", "VGA"};
static char* irq_name[VFIO_PCI_NUM_IRQS] = {"INTX", "MSI", "MISX", "ERR",
                                            "REQ"};

// 82574L BARs (non-prefethcable, 32-bit addressing only)
// BAR0 : Memory BAR
// BAR1 : Flash BAR
// BAR2 : IO BAR
// BAR3 : MSI-X BAR
// BAR4 : Reserved
// BAR5 : Reserved

#ifdef PHYSADDR_MAP
// Convert virtual address to physical address
// https://www.kernel.org/doc/Documentation/vm/pagemap.txt
static uintptr_t virt_to_phys(void* virt) {
    long pagesize = sysconf(_SC_PAGESIZE);
    int fd = open("/proc/self/pagemap", O_RDONLY);
    ASSERT(fd != -1, "failed to open /proc/self/pagemap");
    off_t ret =
        lseek(fd, (uintptr_t)virt / pagesize * sizeof(uintptr_t), SEEK_SET);
    ASSERT(ret != -1, "lseek error");
    uintptr_t entry = 0;
    ssize_t rc = read(fd, &entry, sizeof(entry));
    ASSERT(rc > 0, "read error");
    ASSERT(entry != 0,
           "failed to get physical address for %p (perhaps forgot sudo?)",
           virt);
    close(fd);

    return (entry & 0x7fffffffffffffULL) * pagesize +
           ((uintptr_t)virt) % pagesize;
}
#endif

static inline void write_u32(struct device* dev, int offset, uint32_t value) {
    __asm__ volatile("" : : : "memory");
    *((volatile uint32_t*)(dev->mmio_addr + offset)) = value;
}

static inline uint32_t read_u32(struct device* dev, int offset) {
    __asm__ volatile("" : : : "memory");
    return *((volatile uint32_t*)(dev->mmio_addr + offset));
}

static inline void set_flags_u32(struct device* dev, int offset,
                                 uint32_t flags) {
    write_u32(dev, offset, read_u32(dev, offset) | flags);
}

static inline void clear_flags_u32(struct device* dev, int offset,
                                   uint32_t flags) {
    write_u32(dev, offset, read_u32(dev, offset) & ~flags);
}

static void open_vfio(struct device* dev, int segn, int busn, int devn,
                      int funcn) {
    dev->device_info.argsz = sizeof(struct vfio_device_info);
    dev->group_status.argsz = sizeof(struct vfio_group_status);
    dev->iommu_info.argsz = sizeof(struct vfio_iommu_type1_info);
    for (int i = 0; i < VFIO_PCI_NUM_REGIONS; i++) {
        dev->regs[i].argsz = sizeof(struct vfio_region_info);
    }
    for (int i = 0; i < VFIO_PCI_NUM_IRQS; i++) {
        dev->irqs[i].argsz = sizeof(struct vfio_irq_info);
    }

    // find iommu group for the device
    // `readlink /sys/bus/pci/device/<segn:busn:devn.funcn>/iommu_group`
    char path[128], iommu_group_path[128];
    struct stat st;
    snprintf(path, sizeof(path), "/sys/bus/pci/devices/%04x:%02x:%02x.%01x/",
             segn, busn, devn, funcn);
    int ret = stat(path, &st);
    ASSERT(ret >= 0, "No such device: %s", path);
    strncat(path, "iommu_group", sizeof(path) - strlen(path) - 1);

    int len = readlink(path, iommu_group_path, sizeof(iommu_group_path));
    ASSERT(len > 0, "No iommu_group for device");

    iommu_group_path[len] = '\0';
    char* group_name = basename(iommu_group_path);
    int groupid;
    ret = sscanf(group_name, "%d", &groupid);
    ASSERT(ret == 1, "unknown group");

    // open vfio file
    dev->cfd = open("/dev/vfio/vfio", O_RDWR);
    ASSERT(dev->cfd >= 0, "failed to open /dev/vfio/vfio");

    snprintf(path, sizeof(path), "/dev/vfio/%d", groupid);
    dev->gfd = open(path, O_RDWR);
    ASSERT(dev->gfd >= 0, "failed to open %s", path);

    ret = ioctl(dev->gfd, VFIO_GROUP_GET_STATUS, &dev->group_status);
    ASSERT(
        dev->group_status.flags & VFIO_GROUP_FLAGS_VIABLE,
        "VFIO group is not visible (probably not all devices bound for vfio?)");

    // set container
    ret = ioctl(dev->gfd, VFIO_GROUP_SET_CONTAINER, &dev->cfd);
    ASSERT(ret == 0, "failed to set container");
    // set vfio type (type1 is for IOMMU like VT-d or AMD-Vi)
    ret = ioctl(dev->cfd, VFIO_SET_IOMMU, VFIO_TYPE1_IOMMU);
    ASSERT(ret == 0, "failed to set iommu type");

    // get device descriptor
    snprintf(path, sizeof(path), "%04x:%02x:%02x.%01x", segn, busn, devn,
             funcn);
    dev->fd = ioctl(dev->gfd, VFIO_GROUP_GET_DEVICE_FD, path);
    ASSERT(dev->fd >= 0, "cannot get device fd");
}

static void get_device_info(struct device* dev) {
    int i;
    ioctl(dev->fd, VFIO_DEVICE_GET_INFO, &dev->device_info);

    debug("num_regions: %d", dev->device_info.num_regions);
    debug("flags = CAPS, MMAP, WRITE, READ");
    for (i = 0; i < dev->device_info.num_regions; i++) {
        dev->regs[i].index = i;
        ioctl(dev->fd, VFIO_DEVICE_GET_REGION_INFO, &dev->regs[i]);
        debug("region %d.flags = %d%d%d%d (%s)", i,
              !!(dev->regs[i].flags & VFIO_REGION_INFO_FLAG_CAPS),
              !!(dev->regs[i].flags & VFIO_REGION_INFO_FLAG_MMAP),
              !!(dev->regs[i].flags & VFIO_REGION_INFO_FLAG_WRITE),
              !!(dev->regs[i].flags & VFIO_REGION_INFO_FLAG_READ),
              region_name[i]);
    }

    debug("num_irqs: %d", dev->device_info.num_irqs);
    debug("flags = NORESIZE, AUTOMASKED, MASKABLE, NORESIZE");
    for (i = 0; i < dev->device_info.num_irqs; i++) {
        dev->irqs[i].index = i;
        ioctl(dev->fd, VFIO_DEVICE_GET_IRQ_INFO, &dev->irqs[i]);

        debug("IRQ info %d (%s)", i, irq_name[i]);
        debug("  irq.flags = %d%d%d%d",
              !!(dev->irqs[i].flags & VFIO_IRQ_INFO_NORESIZE),
              !!(dev->irqs[i].flags & VFIO_IRQ_INFO_AUTOMASKED),
              !!(dev->irqs[i].flags & VFIO_IRQ_INFO_MASKABLE),
              !!(dev->irqs[i].flags & VFIO_IRQ_INFO_EVENTFD));
        debug("  irq.index = %d", dev->irqs[i].index);
        debug("  irq.count = %d", dev->irqs[i].count);
    }
}

// Dump device PCI configuration space
// Note that some fields may be virtualized by VFIO
// (thus cannot mmap configuration space)
// To check actual configuration space, `sudo lspci -xxxx -s <device>`
static void dump_configuration_space(struct device* dev) {
    char buf[4096];
    struct vfio_region_info* cs_info = &dev->regs[VFIO_PCI_CONFIG_REGION_INDEX];
    int ret = pread(dev->fd, buf, cs_info->size > 4096 ? 4096 : cs_info->size,
                    cs_info->offset);
    ASSERT(ret >= 0, "pread error");

    int len;
    for (len = ret - 1; len >= 0; len--) {
        if (buf[len] != 0)
            break;
    }
    len = (len + 16) - (len + 16) % 16;

    for (int i = 0; i < len;) {
        printf("%3X: ", i);
        for (int j = 0; j < 16 && i < len; i++, j++) {
            printf("%02X ", (u8)buf[i]);
        }
        printf("\n");
    }
}

void init_vfio(struct device* dev, int segn, int busn, int devn, int func) {
    open_vfio(dev, segn, busn, devn, func);
    get_device_info(dev);
#ifndef NDEBUG
    dump_configuration_space(dev);
#endif
}

// Enable DMA
void enable_bus_master(struct device* dev) {
    struct vfio_region_info* cs_info = &dev->regs[VFIO_PCI_CONFIG_REGION_INDEX];
    char buf[2];
    pread(dev->fd, buf, 2, cs_info->offset + 4);
    *(u16*)(buf) |= 1 << 2;
    pwrite(dev->fd, buf, 2, cs_info->offset + 4);
    debug("PCI configuration space command reg = %04X\n", *(u16*)buf);
}

// Convert virtual address to IOVA
static u64 get_iova(u64 virt_addr, ssize_t size) {
    static u64 _iova = 0;
#if defined(IDENTITY_MAP)
    // Use virtual address as IOVA
    // Note that some architecture only support 3-level page table (39-bit) and
    // cannot use virtual address as IOVA
    return virt_addr;
#elif defined(PHYSADDR_MAP)
    // Use physical address as IOVA
    return (u64)virt_to_phys(virt_addr);
#else
    // Assign IOVA from 0
    u64 ret = _iova;
    _iova += size;
    return ret;
#endif
}

// Allocate rx_ring and DMA buffer
// XXX: should use hugetlb
static u64 init_rx_buf(struct device* dev) {
    struct vfio_iommu_type1_dma_map dma_map = {
        .argsz = sizeof(dma_map),
        .flags = VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE};

    ssize_t size = NUM_OF_DESC * sizeof(struct rdesc);
    dev->rx_ring = mmap(NULL, size, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ASSERT(dev->rx_ring != MAP_FAILED, "failed to mmap rx ring");
    dev->rx_ring_buf_vaddr =
        mmap(NULL, sizeof(void*) * NUM_OF_DESC, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ASSERT(dev->rx_ring_buf_vaddr != MAP_FAILED,
           "failed to mmap rx vaddr buffer");

    // setup iommu for rx_ring
    dma_map.size = NUM_OF_DESC * sizeof(struct rdesc);
    dma_map.vaddr = (u64)dev->rx_ring;
    dma_map.iova = get_iova((u64)dev->rx_ring, size);
    u64 rx_ring_iova = dma_map.iova;
    int ret = ioctl(dev->cfd, VFIO_IOMMU_MAP_DMA, &dma_map);
    ASSERT(ret == 0, "failed to map rx_ring");

    // allocate buffer
    for (int i = 0; i < NUM_OF_DESC; i++) {
        void* buffer = mmap(NULL, BUFSIZE, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        ASSERT(buffer != MAP_FAILED, "failed to mmap rx buffer");

        // setup iommu for buffer
        dma_map.size = BUFSIZE;
        dma_map.vaddr = (u64)buffer;
        dma_map.iova = get_iova((u64)buffer, BUFSIZE);
        dev->rx_ring_buf_vaddr[i] = buffer;
        ret = ioctl(dev->cfd, VFIO_IOMMU_MAP_DMA, &dma_map);
        ASSERT(ret == 0, "failed to map rx buffer %d (%s)\n", i,
               strerror(errno));
        dev->rx_ring[i].buffer = dma_map.iova;
    }
    return rx_ring_iova;
}

// allocate tx_ring
// XXX: should use hugetlb
static u64 init_tx_buf(struct device* dev) {
    struct vfio_iommu_type1_dma_map dma_map = {
        .argsz = sizeof(dma_map),
        .flags = VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE};

    ssize_t size = NUM_OF_DESC * sizeof(struct tdesc);
    dev->tx_ring = mmap(NULL, size, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ASSERT(dev->tx_ring != MAP_FAILED, "failed to mmap tx ring");
    dev->tx_ring_buf_vaddr =
        mmap(NULL, sizeof(void*) * NUM_OF_DESC, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ASSERT(dev->tx_ring_buf_vaddr != MAP_FAILED,
           "failed to mmap tx vaddr buffer");

    // setup iommu for tx_ring
    dma_map.iova = get_iova((u64)dev->tx_ring, size);
    dma_map.size = size;
    dma_map.vaddr = (u64)dev->tx_ring;
    u64 tx_ring_iova = dma_map.iova;
    int ret = ioctl(dev->cfd, VFIO_IOMMU_MAP_DMA, &dma_map);
    ASSERT(ret == 0, "failed to map dev->tx_ring");

    // allocate buffer
    for (int i = 0; i < NUM_OF_DESC; i++) {
        void* buffer = mmap(NULL, BUFSIZE, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        ASSERT(buffer != MAP_FAILED, "failed to mmap tx buffer");

        // setup iommu for buffer
        dma_map.iova = get_iova((u64)buffer, BUFSIZE);
        dma_map.size = BUFSIZE;
        dma_map.vaddr = (u64)buffer;
        dev->tx_ring_buf_vaddr[i] = buffer;
        ret = ioctl(dev->cfd, VFIO_IOMMU_MAP_DMA, &dma_map);
        ASSERT(ret == 0, "failed to map tx buffer %d", i);
        dev->tx_ring[i].buffer = dma_map.iova;
    }
    return tx_ring_iova;
}

// unmask INTx
static void unmask_intx(struct device* dev) {
    char irq_set_buf[sizeof(struct vfio_irq_set)];
    struct vfio_irq_set* irq_set = (struct vfio_irq_set*)irq_set_buf;
    irq_set->argsz = sizeof(struct vfio_irq_set);
    irq_set->count = 1;
    irq_set->flags = VFIO_IRQ_SET_DATA_NONE | VFIO_IRQ_SET_ACTION_UNMASK;
    irq_set->index = VFIO_PCI_INTX_IRQ_INDEX;
    irq_set->start = 0;
    int ret = ioctl(dev->fd, VFIO_DEVICE_SET_IRQS, irq_set);
    ASSERT(ret == 0, "faield to unmask INTx interrupt");
}

// Enable INTx interrupt
static void enable_intx(struct device* dev) {
    debug("Use INTx interrupt");
    struct vfio_irq_set* irq_set;
    char irq_set_buf[sizeof(struct vfio_irq_set) + sizeof(int)];
    irq_set = (struct vfio_irq_set*)irq_set_buf;
    irq_set->argsz = sizeof(irq_set_buf);
    irq_set->count = 1;
    irq_set->flags = VFIO_IRQ_SET_DATA_EVENTFD | VFIO_IRQ_SET_ACTION_TRIGGER;
    irq_set->index = VFIO_PCI_INTX_IRQ_INDEX;
    irq_set->start = 0;
    dev->efd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    debug("efd = %d\n", dev->efd);
    ASSERT(dev->efd >= 0, "efd init failed");
    *(int*)&irq_set->data = dev->efd;
    int ret = ioctl(dev->fd, VFIO_DEVICE_SET_IRQS, irq_set);
    ASSERT(ret == 0, "faield to enable INTx interrupt");

    unmask_intx(dev);
}

// Enable MSI interrupt
// 82574L only has one MSI interrupt vector
// so basically same as INTx from driver's point of view
static void enable_msi(struct device* dev) {
    debug("Use MSI interrupt");
    struct vfio_irq_set* irq_set;
    char irq_set_buf[sizeof(struct vfio_irq_set) + sizeof(int)];
    irq_set = (struct vfio_irq_set*)irq_set_buf;
    irq_set->argsz = sizeof(irq_set_buf);
    irq_set->count = 1;
    irq_set->flags = VFIO_IRQ_SET_DATA_EVENTFD | VFIO_IRQ_SET_ACTION_TRIGGER;
    irq_set->index = VFIO_PCI_MSI_IRQ_INDEX;
    irq_set->start = 0;
    dev->efd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    debug("efd = %d\n", dev->efd);
    ASSERT(dev->efd >= 0, "efd init failed");
    *(int*)&irq_set->data = dev->efd;
    int ret = ioctl(dev->fd, VFIO_DEVICE_SET_IRQS, irq_set);
    ASSERT(ret == 0, "faield to enable MSI interrupt");
}

// Enable MSI-X Interrupt
// 82574L has five MSI-X interrupt vectors
static void enable_msix(struct device* dev) {
    debug("Use MSI-X interrupt");
    struct vfio_irq_set* irq_set;
    char irq_set_buf[sizeof(struct vfio_irq_set) +
                     sizeof(int) * MAX_MSIX_VECTOR_NUM];
    irq_set = (struct vfio_irq_set*)irq_set_buf;
    irq_set->argsz = sizeof(irq_set_buf);
    irq_set->count = MAX_MSIX_VECTOR_NUM;
    irq_set->flags = VFIO_IRQ_SET_DATA_EVENTFD | VFIO_IRQ_SET_ACTION_TRIGGER;
    irq_set->index = VFIO_PCI_MSIX_IRQ_INDEX;
    irq_set->start = 0;
    for (int i = 0; i < MAX_MSIX_VECTOR_NUM; i++) {
        dev->efds[i] = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
        ASSERT(dev->efds[i] >= 0, "efd init failed");
    }
    memcpy((int*)&irq_set->data, dev->efds, sizeof(dev->efds));
    int ret = ioctl(dev->fd, VFIO_DEVICE_SET_IRQS, irq_set);
    ASSERT(ret == 0, "faield to enable MSI-X interrupt");

    // Setup MSI-X interrupt vector
    //   RxQ0  => 0
    //   RxQ1  => 1
    //   TxQ0  => 2
    //   TxQ1  => 3
    //   Other => 4
    write_u32(dev, IVAR,
              IVAR_EN_RXQ0 | IVAR_EN_RXQ1 | IVAR_EN_TXQ0 | IVAR_EN_TXQ1 |
                  IVAR_EN_OTHER | 0 << IVAR_RXQ0_VEC_SHIFT |
                  1 << IVAR_RXQ1_VEC_SHIFT | 2 << IVAR_TXQ0_VEC_SHIFT |
                  3 << IVAR_TXQ1_VEC_SHIFT | 4 << IVAR_OTHER_VEC_SHIFT);
}

// Disable all interrupts
static void disable_interrupt(struct device* dev) {
    write_u32(dev, IMC, 0xffffffff);
}

// Reset device
static void reset(struct device* dev) {
    set_flags_u32(dev, CTRL_, CTRL_RST);
    usleep(500 * 1000);
}

// Set general configuration
static void global_configuration(struct device* dev) {
    // CTRL.FD = 1
    set_flags_u32(dev, CTRL_, CTRL_FD);
    // GCR[22] = 1
    write_u32(dev, GCR, read_u32(dev, GCR) | 1 << 22);

    // no flow control
    write_u32(dev, FCAH, 0);
    write_u32(dev, FCAL, 0);
    write_u32(dev, FCT, 0);
    write_u32(dev, FCTTV, 0);
}

// Initialize some statistics registers
// NOTE: All statistics registers reset when read
static void init_stat_regs(struct device* dev) {
    read_u32(dev, MPC);
    read_u32(dev, GPRC);
    read_u32(dev, GPTC);
    read_u32(dev, GORCL);
    read_u32(dev, GORCH);
    read_u32(dev, GOTCL);
    read_u32(dev, GOTCH);
}

// Set link up
static void linkup(struct device* dev) {
    set_flags_u32(dev, CTRL_, CTRL_SLU);
    int retry = 50;
    printf("waiting linkup.");
    while (!(read_u32(dev, STATUS) & 0x2) && retry--) {
        printf(".");
        fflush(stdout);
        usleep(500 * 1000);
    }
    printf("\n");
    ASSERT(read_u32(dev, STATUS) & 0x2, "failed to link up");
}

// Receive Initialization
static void init_receive(struct device* dev) {
    u64 rx_ring_iova = init_rx_buf(dev);
    debug("rx ring iova = %08lX", rx_ring_iova);
    write_u32(dev, RDLEN, NUM_OF_DESC * sizeof(struct rdesc));
    write_u32(dev, RDBAL, (u32)(rx_ring_iova & 0xFFFFFFFFull));
    write_u32(dev, RDBAH, (u32)(rx_ring_iova >> 32));
    write_u32(dev, RDH, 0);
    write_u32(dev, RDT, NUM_OF_DESC - 1);

    // Enable receive
    write_u32(dev, RCTL,
              RCTL_EN |         /* Enable */
                  RCTL_UPE |    /* Unicast Promiscuous Enable*/
                  RCTL_MPE |    /* Multicast Promiscuous Enable */
                  RCTL_BSIZE1 | /* BSIZE == 11b => 4096 bytes (if BSEX = 1) */
                  RCTL_BSIZE2 | /* */
                  RCTL_LPE |    /* Long Packet Enable */
                  RCTL_BAM |    /* Broadcast Accept Mode */
                  RCTL_BSEX |   /* Buffer Size Extension */
                  RCTL_SECRC    /* Strip Ethernet CRC from incoming packet */
    );
}

// Transmit Initialization
static void init_transmit(struct device* dev) {
    u64 tx_ring_iova = init_tx_buf(dev);
    debug("tx ring iova = %08lX", tx_ring_iova);
    write_u32(dev, TDBAH, (u32)((u64)tx_ring_iova >> 32));
    write_u32(dev, TDBAL, (u32)((u64)tx_ring_iova & 0xFFFFFFFFull));
    write_u32(dev, TDLEN, NUM_OF_DESC * sizeof(struct tdesc));
    write_u32(dev, TDH, 0);
    write_u32(dev, TDT, 0);

    // Enable transmit
    write_u32(dev, TCTL,
              TCTL_EN |    /* Enable */
                  TCTL_PSP /* Pad short packets */
    );
}

// enable interrupt
// 1. setup eventfd and enable device interrupts
// 2. set IMS register appropriately
static void enable_interrupt(struct device* dev) {
#if defined(MSI)
    enable_msi(dev);
#elif defined(MSIX)
    enable_msix(dev);
#else
    enable_intx(dev);
#endif

    write_u32(dev, IMS,
              IMS_LSC |     /* Link State Change */
                  IMS_RXT | /* Receiver Timer Interrupt */
                  IMS_RXDMT /* Receiver descriptor minimum threshold hit */
    );

#ifdef TXINT
    set_flags_u32(dev, IMS, IMS_TXDW); /* Transmit Descriptor Written Back */
    // add some interrupt delay
    // (otherwise ICR_TXDW will be cleared before an interrupt arrives)
    write_u32(dev, TIDV, 1);
#endif
#ifdef MSIX
    set_flags_u32(dev, IMS, IMS_RXQ0 | IMS_TXQ0 | IMS_OTHER);
#endif
    debug("IMS: %08X", read_u32(dev, IMS));
}

void init_device(struct device* dev) {
    // mmap BAR0
    struct vfio_region_info* bar0_info = &dev->regs[VFIO_PCI_BAR0_REGION_INDEX];
    dev->mmio_addr = mmap(NULL, bar0_info->size, PROT_READ | PROT_WRITE,
                          MAP_SHARED, dev->fd, bar0_info->offset);
    ASSERT(dev->mmio_addr != MAP_FAILED, "mmap failed");

    // c.f. manual 4.6

    /* 1. Disable Interrupts */
    disable_interrupt(dev);

    /* 2. Global reset & general configuration */
    reset(dev);
    disable_interrupt(dev);
    global_configuration(dev);

    /* 3. Setup the PHY and the link */
    linkup(dev);

    /* 4. Initialize statistical counters */
    init_stat_regs(dev);

    /* 5. Initialize Receive */
    init_receive(dev);

    /* 6. Initialize Transmit */
    init_transmit(dev);

#ifndef POLL
    /* 7. Enable Interrupts */
    enable_interrupt(dev);
#endif

    /* dump some information */
    u32 rah0 = read_u32(dev, RAH0);
    u32 ral0 = read_u32(dev, RAL0);
    debug("MAC: %02X:%02X:%02X:%02X:%02X:%02X", (ral0)&0xff, (ral0 >> 8) & 0xff,
          (ral0 >> 16) & 0xff, (ral0 >> 24) & 0xff, (rah0)&0xff,
          (rah0 >> 8) & 0xff);
    debug("CTRL: %08X", read_u32(dev, CTRL_));
    u32 status = read_u32(dev, STATUS);
    debug("STATUS: %08X", status);
    debug("  FD = %d", status & 0x1);
    debug("  LU = %d", (status >> 1) & 0x1);
    debug("  SPEED = %d", (status >> 6) & 0x3);
    debug("RCTL:  %08X", read_u32(dev, RCTL));
    debug("RDBAL: %08X, RDBAH=%08X", read_u32(dev, RDBAL),
          read_u32(dev, RDBAH));
    debug("RDLEN: %08X", read_u32(dev, RDLEN));
    debug("TCTL:  %08X", read_u32(dev, TCTL));
    debug("TDBAL: %08X, TDBAH=%08X", read_u32(dev, TDBAL),
          read_u32(dev, TDBAH));
    debug("TDLEN: %08X", read_u32(dev, TDLEN));
}

void dump_pkt(void* addr) {
    struct ethhdr* eth = addr;

    printf("src=%02X:%02X:%02X:%02X:%02X:%02X\n", eth->h_source[5],
           eth->h_source[4], eth->h_source[3], eth->h_source[2],
           eth->h_source[1], eth->h_source[0]);

    printf("dst=%02X:%02X:%02X:%02X:%02X:%02X\n", eth->h_dest[5],
           eth->h_dest[4], eth->h_dest[3], eth->h_dest[2], eth->h_dest[1],
           eth->h_dest[0]);
    printf("proto=%04X\n", ntohs(eth->h_proto));
}

// transmit packet
void tx(struct device* dev, void* buffer, ssize_t len) {
    ASSERT(len <= BUFSIZE, "too much large packet: %lu", len);
    u32 tdt = read_u32(dev, TDT);
    u32 tdh = read_u32(dev, TDH);
    debug("tdh=%u, tdt=%u", tdh, tdt);
    if (tdh != ((tdt + 1) % NUM_OF_DESC)) {
        memcpy(dev->tx_ring_buf_vaddr[tdt], buffer, len);
        dev->tx_ring[tdt].length = len;
        dev->tx_ring[tdt].ifcs = 1;  // insert FCS
        dev->tx_ring[tdt].eop = 1;   // end of packets
#ifdef TXINT
        dev->tx_ring[tdt].rs = 1;  // report status
#ifndef MSIX
        // In MSI-X, IDE bit should not be set (manual 7.2.8)
        dev->tx_ring[tdt].ide = 1;  // interrupt delay enable
#endif
#endif
        write_u32(dev, TDT, (tdt + 1) % NUM_OF_DESC);
    }
}

static void set_source_mac(struct device* dev, struct ethhdr* eth) {
    u32 rah0 = read_u32(dev, RAH0);
    u32 ral0 = read_u32(dev, RAL0);
    eth->h_source[5] = (rah0 >> 8) & 0xff;
    eth->h_source[4] = (rah0)&0xff;
    eth->h_source[3] = (ral0 >> 24) & 0xff;
    eth->h_source[2] = (ral0 >> 16) & 0xff;
    eth->h_source[1] = (ral0 >> 8) & 0xff;
    eth->h_source[0] = (ral0)&0xff;
}

void set_ether(struct device* dev, void* addr) {
    struct ethhdr* eth = addr;
    memcpy(eth->h_source, eth->h_dest, 6);
    set_source_mac(dev, eth);
}

// 1. dump receive packtes
// 2. echo pakcet if needed
// 3. clear desc and advance RDH
u32 rx(struct device* dev, u32 idx) {
    dump_pkt(dev->rx_ring_buf_vaddr[idx]);
#ifdef ECHO
    // note that we can do this through zero-copy
    set_ether(dev, dev->rx_ring_buf_vaddr[idx]);
    tx(dev, dev->rx_ring_buf_vaddr[idx], dev->rx_ring[idx].length);
#endif
    // clear desc
    dev->rx_ring[idx].dd = 0;
    u32 head = read_u32(dev, RDH);
    if (head != idx) {
        write_u32(dev, RDT, idx);
    }
    return (idx + 1) % NUM_OF_DESC;
}

// Poll receive descriptor
static void poll(struct device* dev) {
    printf("start polling\n");
    u32 rx_idx = 0;
    int cnt = 0;
    while (1) {
        if (dev->rx_ring[rx_idx].dd) {  // descriptor done
            rx_idx = rx(dev, rx_idx);
            cnt += 1;
        }
    }
}

// Wait interrupt using epoll_wait and handle it when it arrives
// Note that we can simply use `read(dev->efd, &u, sizeof(u))` for INTx and MSI
// (eventfd should be created without `EFD_NONBLOCK`)
static void handle_intr(struct device* dev) {
    // Create epoll fd
    dev->epfd = epoll_create1(EPOLL_CLOEXEC);
    ASSERT(dev->epfd >= 0, "failed to create epoll fd");

    // Add eventfd to epoll
#ifndef MSIX  // INTx, MSI
    struct epoll_event ev = {.events = EPOLLIN | EPOLLPRI, .data.fd = dev->efd};
    int ret = epoll_ctl(dev->epfd, EPOLL_CTL_ADD, dev->efd, &ev);
    ASSERT(ret == 0, "cannot add fd to epoll");
#else
    for (int i = 0; i < MAX_MSIX_VECTOR_NUM; i++) {
        struct epoll_event ev = {.events = EPOLLIN | EPOLLPRI,
                                 .data.fd = dev->efds[i]};
        int ret = epoll_ctl(dev->epfd, EPOLL_CTL_ADD, dev->efds[i], &ev);
        ASSERT(ret == 0, "cannot add fd to epoll");
    }
#endif

    struct epoll_event evs;
    u32 rx_idx = 0;
    printf("waiting interrupts...\n");
    for (;;) {
        // blocking wait
        int rc = epoll_wait(dev->epfd, &evs, 1, -1);
        ASSERT(rc > 0, "epoll error");
        debug("epoll return: %d", rc);
        u64 u;
        debug("evs fd = %d", evs.data.fd);
        ssize_t s = read(evs.data.fd, &u, sizeof(u));
        ASSERT(s == sizeof(u), "efd read failed");

        u32 icr = read_u32(dev, ICR);
        debug("ICR = %08x", icr);

#if !defined(MSIX)
        if (icr & (IMS_RXDMT | IMS_RXT)) {
            ASSERT(dev->rx_ring[rx_idx].dd == 1, "dd != 1");
            debug("receive interrupt");
            rx_idx = rx(dev, rx_idx);
        }
        if (icr & IMS_LSC) {
            debug("link state change");
        }
        if (icr & (IMS_TXDW)) {
            debug("transmit interrupt");
        }
#else
        if (evs.data.fd == dev->efds[0]) {  // RX0
            ASSERT(dev->rx_ring[rx_idx].dd == 1, "dd != 1");
            debug("RX0 interrupt");
            rx_idx = rx(dev, rx_idx);
        } else if (evs.data.fd == dev->efds[1]) {  // RX1
            debug("RX1 interrupt");
        } else if (evs.data.fd == dev->efds[2]) {  // TX0
            debug("TX0 interrupt");
        } else if (evs.data.fd == dev->efds[3]) {  // TX1
            debug("TX1 interrupt");
        } else {
            debug("Other interrupt");
        }
#endif

        // clear interrupt
        write_u32(dev, ICR, read_u32(dev, ICR) | 0xFFFFFFFF);

#if !defined(MSI) && !defined(MSIX)
        // INTx is automatically masked by the VFIO INTx handler
        unmask_intx(dev);
#endif
    }
}

// Construct dummy packet
static ssize_t create_dummy_packet(struct device* dev, char* buf) {
    struct ethhdr* eth = (struct ethhdr*)buf;
    set_source_mac(dev, eth);
    eth->h_dest[0] = 0xFF;
    eth->h_dest[1] = 0xFF;
    eth->h_dest[2] = 0xFF;
    eth->h_dest[3] = 0xFF;
    eth->h_dest[4] = 0xFF;
    eth->h_dest[5] = 0xFF;
    eth->h_proto = htons(0x0800);  // IPv4
    struct iphdr* ip = (struct iphdr*)((char*)eth + sizeof(struct ethhdr));
    ip->ihl = 5;
    ip->version = 4;
    ip->tot_len = htons(sizeof(struct ip) + sizeof(struct udphdr) + 1);
    ip->protocol = 17;  // UDP
    ip->ttl = 255;
    ip->saddr = htonl(0xc0a8140a);  // 192.168.20.10
    ip->daddr = htonl(0xc0a81414);  // 192.168.20.20
    // XXX: Should calculate checksum
    ip->check = 0;
    struct udphdr* udp = (struct udphdr*)((char*)ip + sizeof(struct ip));
    udp->uh_sport = htons(10000);
    udp->uh_dport = htons(20000);
    udp->uh_ulen = htons(sizeof(struct udphdr) + 1);
    udp->uh_sum = 0;
    buf[sizeof(struct ethhdr) + sizeof(struct ip) + sizeof(struct udphdr)] =
        'a';

    return sizeof(struct ethhdr) + sizeof(struct ip) + sizeof(struct udphdr) +
           1;
}

// Send a dummy packet when pressing a key
static void pkt_send(struct device* dev) {
    char buf[4096];
    memset(buf, 0, 4096);
    ssize_t len = create_dummy_packet(dev, buf);
    while (1) {
        getchar();
        tx(dev, buf, len);
        debug("send pkt");
    }
}

// Compile flag (() is default)
//  - (mapping from zero), IDENTITY_MAP, PHYSADDR_MAP
//  - (INTx), MSI, MSIX
//  - (interrupt), POLL, PKTSEND
//  - (no echo), ECHO
//  - (no tx interrupts), TXINT
//
//  note that interrupts option is only valid when do `handle_intr()`

int main(int argc, char* argv[]) {
    int segn, busn, devn, funcn, i;
    struct device dev;

    if (argc < 2 || sscanf(argv[1], "%04x:%02x:%02x.%d", &segn, &busn, &devn,
                           &funcn) != 4) {
        printf("Usage: %s ssss:bb:dd.f\n", argv[1]);
        return -1;
    }

    init_vfio(&dev, segn, busn, devn, funcn);
    enable_bus_master(&dev);
    init_device(&dev);

#if defined(POLL)
    poll(&dev);
#elif defined(PKTSEND)
    pkt_send(&dev);
#else
    handle_intr(&dev);
#endif

    // XXX: It's better to do cleanup

    return 0;
}

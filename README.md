# vfio-e1000
Simple Intel 1GbE network driver implementation using VFIO.

## Binding vfio-pci driver
- Before using VFIO, you need to bind vfio-pci driver to the NIC like the following.

```sh
% lspci -nn | grep -i Ether
86:00.0 Ethernet controller [0200]: Intel Corporation 82574L Gigabit Network Connection [8086:10d3]
% sudo modprobe vfio-pci
% echo 0000:86:00.0 | sudo tee -a /sys/bus/pci/devices/0000:86:00.0/driver/unbind
% echo 8086 10d3 | sudo tee -a /sys/bus/pci/drivers/vfio-pci/new_id
% sudo chown -R group:user /dev/vfio/66
```

- You can use [vfio-pci-bind](https://github.com/andre-richter/vfio-pci-bind)

## Compile
- `gcc -o e1000 e1000.c`
    - Use INTx, dump received packets
- `gcc -o e1000 e1000.c -DPOLL`
    - polling instead of interrupts
- `gcc -o e1000 e1000.c -DMSIX -DTXINT -DECHO`
    - use MSIX, enable Tx interrupt, echo received packets
- For more detail, see the source

## Usage
- `./e1000 <segment:bus:device.function>`
    - for example, `./e1000 0000:01:00.0`

## Note
- If you get out of memory error, probably you need to increase the memlock limits.
    - VFIO automatically lock the DMA memory region so as not to be moved.
    - Check current memlock liimit: `prlimit -l`
    - Temporary increase the limit: `sudo prlimit --memlock=-1 ./e1000 0000:01:00.0`
    - To make the configuration permanent, edit `/etc/security/limits.conf`
- I only tested this with 82574L on Intel CPU.

## Requirements
- IOMMU (VT-d for Intel)
    - VFIO supports no IOMMU mode, but this driver currently does not.

## Reference
- https://www.kernel.org/doc/Documentation/vfio.txt
- Intel® 82574 GbE Controller Family Datasheet, https://www.intel.ca/content/dam/doc/datasheet/82574l-gbe-controller-datasheet.pdf
- MINIX e1000, https://github.com/Stichting-MINIX-Research-Foundation/minix/tree/master/minix/drivers/net/e1000
- FreeBSD e1000, https://github.com/freebsd/freebsd/tree/master/sys/dev/e1000
- Redox e1000, https://github.com/redox-os/drivers/blob/master/e1000d/
- snabb driver, https://github.com/snabbco/snabb/blob/master/src/apps/intel_mp/intel_mp.lua
    - old version, https://github.com/anttikantee/snabbswitch/blob/master/src/apps/intel/intel.lua

## License
[MIT](https://opensource.org/licenses/MIT)

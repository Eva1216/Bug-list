

![image](https://github.com/WhooAmii/Bug-list/blob/master/QEMU-KVM/test.gif)

The ehci controller and usb-tablet device are used in the default configuration of libvirt
Vulnerabilities in QEMU's USB backend implementation can cause virtual machines to escape.
This is caused by the USB controller communicating with the USB device.
URB packet communication sequence: ehci_execute->usb_handle_packet->usb_process_one->do_token_setup/in/out
Cause of vulnerability:
When entering do_token_setup, enter this code
  usb_packet_copy(p, s->setup_buf, p->iov.size);
   s->setup_index = 0;
    p->actual_length = 0;
    s->setup_len = (s->setup_buf[7] << 8) | s->setup_buf[6];
    if (s->setup_len> sizeof(s->data_buf)) {
        fprintf(stderr,
                "usb_generic_handle_packet: ctrl buffer too small (%d> %zu)\n",
                s->setup_len, sizeof(s->data_buf));
        p->status = USB_RET_STALL;
        return;
  The data of s->setup_buf can be controlled. We noticed that s->setup_len can become larger than sizeof(s->data_buf) = 0x1000. Although the function returns later, a large value is stored in s->setup_len in.
Then we check do_token_in/out again, the following code
switch(s->setup_state) {
...
case SETUP_STATE_DATA:
        if (s->setup_buf[0] & USB_DIR_IN) {
            int len ​​= s->setup_len-s->setup_index;
            if (len> p->iov.size) {
                len = p->iov.size;
            }
            usb_packet_copy(p, s->data_buf + s->setup_index, len);
            s->setup_index += len;
            if (s->setup_index >= s->setup_len) {
                s->setup_state = SETUP_STATE_ACK;
            }
            return;
        }
usb_packet_copy copies the data, do_token_in transmits the device data to the user, do_token_out transmits the user data to the device, the transmission size is MIN (p->setup_len,iov_size), iov_size is increased by qemu_sglist_add, and the maximum can reach 0x5000. So we can theoretically Transfer 0x5000 size data to s->data_buf, or copy 0x5000 size data from s->data_buf. But the size of s->data_buf is only 0x1000 size, causing out-of-bounds read and out-of-bounds write.

We noticed that s->setup_state needs to be SETUP_STATE_DATA, which is assigned in do_token_setup. When we pass in a large length, it will return the incorrect assignment s->setup_state. But it can be bypassed by the following steps.
1.do_token_setup(len=0xff);//set s->setup_state=SETUP_STATE_DATA
2.do_token_setup(len=0xffff);//set s->setup_len=0xffff,
3.do_token_in/out (read and write out of bounds)
Complete utilization process:
usbdevice{
...
uint8_t setup_buf[8];
 uint8_t data_buf[4096];
    int32_t remote_wakeup;
    int32_t setup_state;
    int32_t setup_len;
    int32_t setup_index;

    USBEndpoint ep_ctl;
    USBEndpoint ep_in[USB_MAX_ENDPOINTS];
    USBEndpoint ep_out[USB_MAX_ENDPOINTS];
...
}
1. Read the address of the usbdevice object through out-of-bounds reading, we can read it from ep_ctl->dev.
2. At this time, we can overwrite the value of setup_index by writing out of bounds, and achieve arbitrary address writing by controlling setup_index+usbdevice_addr=destination address.
3. We also need to obtain any address reading function, setup_buf[0] controls the writing direction, and can only be modified by do_token_setup. Since we used out-of-bounds writing in the second step, setup_buf[0] is the writing direction, so only Can enter the write operation, cannot read.
Bypass method: set setup_index=0xfffffff8, write out of bounds again, modify the value of setup_buf[0] and modify setup_index again to the address you want to read to achieve arbitrary address reading
4. Read the contents of the usbdevice object at any address to get the ehcistate object address, and read the contents of the ehcistate object at any address to get the ehci_bus_ops_companion address. This address is located in the program data section. At this time, we can get the program load address and system@plt address.
5.Fake the irq structure in data_buf.
6. Hijack the irq object in ehcistate as a forged structure.
7. Read the register through mmio to trigger ehci_update_irq, execute system("xcalc"). Complete the use

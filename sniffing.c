#include <stdio.h>
#include <pcap.h>

int main (int argc, char *argv[]) {
  char *dev, errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *handle;

  dev = pcap_lookupdev(errbuf);

  handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "Couldn't open device: %s\n", dev, errbuf);
    return 2;
  }

  printf("Using device: %s\n", dev);

  if (pcap_datalink(handle) != DLT_EN10MB) {
    fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", dev);
    return 2;
  }

  printf("Device %s supports Ethernet headers.\n", dev);
  return 0;
}

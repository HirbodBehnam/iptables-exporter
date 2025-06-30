# iptables Traffic Exporter

Export iptables metric of traffic for some IP addresses as Prometheus metrics. It will manager the iptables chains itself.

## Usage

You only need to specify the addresses which you willing to monitor their upload and download. For example, you can set it like this: `192.168.254.100,192.168.254.101,192.168.254.102`

```
Usage of iptables-exporter:
  -ips string
        List of ip addresses to monitor, comma seperated
  -listen-address string
        The address to listen on for HTTP requests. (default ":8080")
  -update-interval int
        Update interval in seconds. (default 15)
```
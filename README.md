# SSDP Proxy
I recently moved my Roku devices to their own isolated vlan.  Unfortunately this meant that my Roku app was not able to find my Roku devices.  Unlike other devices like Google chromecasts, or AppleTVs that use mDNS, Roku uses SSDP to discover devices.  This proxy will allow your Roku app to find Roku devices on a different subnet.

I borrowed the base code for this project from: https://github.com/ZeWaren/python-upnp-ssdp-example.git

Run this proxy on some gateway device that has access to both your Trusted and Non Trusted vlans.  Be sure to changed the `TRUSTED_IP` and `NONTRUSTED_IP` settings in the `ssdp_proxy.py` script to your IP address attached to each vlan.

## igmpproxy
This problem can also be resolved using off the shelf `igmpproxy`.  I mostly did this as an SSDP learning exercsise, however, this proxy offers 2 benefits:
1.  Will work even when the client sets TTL=1.  Though this can also be fixed with iptables mangle rules.
2.  Using igmpproxy you have to unconditionally open UDP port 1900.  This proxy does not require this port to be open.

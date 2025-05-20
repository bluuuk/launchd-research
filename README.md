# Launchd Research

This project enables good faith security researchers to investigate the iOS sandbox from different app perspectives. As sandbox profiles are huge in LOC, undocumented, and hard to debug with a compiler(which Apple does not ship for iOS), we build a tool set to investigate system services, aka daemons and XPC Services. Works on iOS 15.6 and tested with iOS 18.4 on an iPad. 

# Scripts

- `launchd_get_out_of_my_way.js`
    - Like AMFI get out of my way, we can use this script to halt sandbox checks for mach lookups. Use with parameter 
        - `{"pid":1234}` to target a specific pid for incoming requests.
        - `{"verbose":true}` to have verbose connection output.
    - We target the `mach-lookup` operation for `sandbox_check_by_audit_token` to bypass the internal sandbox checks.
- `entitlement_get_out_of_my_way.js`
    - Like AMFI get out of my way, we can use this script to modify entitlement checks in programs. Use with parameter 
        - `{"pid":1234}` to target a specific pid for incoming requests.
        - `{"verbose":true}` to have verbose output.
    - As entitlement values are context specific, use the commented out `this.shouldBypass` to replace with custom values.

## Launchd get out of my way

To get a default view on reachable services, we developed a convenient option to sidestep sandbox checks in launchd. If no pid is supplied, **all** `mach-lookup` sandbox requests are allowed. To target a specific process, adjust the pid.

```shell
frida -U -p 1 -l launchd_get_out_of_my_way.js -P '{"pid":-1,"verbose":true}'
```

### Entitlements get out of my way

Observe entitlement checks and replace return values if needed. All XPC-functions reference `__xpc_copy_entitlements_data`, which I can't hook via frida, so I only focus the high level API of `XPC` + `SecTaskCopy`. Both functions end up using the same system call `int csops_audittoken(pid_t pid, uint32_t ops, user_addr_t useraddr, user_size_t usersize, user_addr_t uaudittoken)`, which is documented [here](https://github.com/apple-oss-distributions/xnu/blob/8d741a5de7ff4191bf97d57b9f54c2f6d4a15585/bsd/kern/syscalls.master#L265C1-L266C138).

To target a specific process, adjust the pid. We left the callback `onLeave` blank, which can modify the return value if needed. 

```shell
frida -U -n nehelper -l entitlement_get_out_of_my_way.js -P '{"pid":-1,"verbose":true}'
```

### Further work

The `xpctest` can also be injected into other services. However, we don't need step 2) and 3) as exploring the service reachability once sufficient. 

While playing with the contats app, I observed the lookup/register number `3` and `4825`

```
Contacts(4825): mach-register(Unknown(3)) -> com.apple.assistant.contextprovider.com.apple.MobileAddressBook => ACCEPT
Contacts(4825): mach-lookup(Unknown(3)) -> com.apple.assistant.contextprovider.com.apple.MobileAddressBook => ACCEPT
Contacts(4825): mach-register(Unknown(3)) -> com.apple.assistant.contextprovider.com.apple.MobileAddressBook => ACCEPT
Contacts(4825): mach-lookup(UnkContacts(4825): mach-register(Unknown(3)) -> com.apple.assistant.contextprovider.com.apple.MobileAddressBook => ACCEPT
nown(3)) -> com.apple.assistant.contextprovider.com.apple.MobileAddressBook => ACCEPT
```

# License

MIT

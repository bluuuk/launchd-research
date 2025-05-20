# XPC Scanner

This project enables good faith security researchers to investigate the iOS sandbox from different app perspectives. As sandbox profiles are huge in LOC, undocumented, and hard to debug with a compiler(which Apple does not ship for iOS), we build a tool set to investigate system services, aka daemons and XPC Services. Works on iOS 15.6 and tested with iOS 18.4 on an iPad. 

## Scripts

- `servicenames.js`
    - Gets all service names for the *system* domain for daemons and XPC Services.
- `xpctest.js`
    - Evaluates if for a given service name, we can reach it. We use `xpc_connection_copy_invalidation_reason` to infer if the sandbox restricts access. The `xpctest` name is due to the usage of the `xpc` API to establish connections.
    - Important methods are:
        - `evaluate_sandbox()` -> for all service    
        - `xpctest(name)` -> for a single service    
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

## Usage

Afterwards, type in `evaluate_sandbox` to obtain results.

## Launchd get out of my way

To get a default view on reachable services, we developed a convenient option to sidestep sandbox checks in launchd. If no pid is supplied, **all** `mach-lookup` sandbox requests are allowed. To target a specific process, adjust the pid.

```shell
frida -U -p 1 -l launchd_get_out_of_my_way.js -P '{"pid":-1,"verbose":true}'
```

### Entitlements get out of my way

Observe entitlement checks and replace return values if needed. All XPC-functions reference `__xpc_copy_entitlements_data`, which I can't hook via frida, so I only focus the high level API of `XPC` + `SecTaskCopy`. To target a specific process, adjust the pid.

```shell
frida -U -n nehelper -l entitlement_get_out_of_my_way.js -P '{"pid":-1,"verbose":true}'
```

## Experiment 

### Preparation

Build a default app and deploy it to the iPhone/iPad via Xcode. Then [trust the developer](https://www.applivery.com/docs/mobile-app-distribution/troubleshooting/mobile-app-distribution-all/untrusted-enterprise-developer/), if not done:

- Navigate to Settings > General > Device Management.
- Select the developer. 
- Press Trust [Developer].
- Select Trust.

### Execution

0. Set bash variable for target + create a directory for results(related to your device). Please put a real `iosversion` and `hardwareversion` in.

```bash
target="thesis.testetsttest"
output="results/iosversion_hardwareversion"
mkdir "$output"
```

1. Inject into empty app to get all reachable service through the sandbox

```bash
frida -U -f "$target" -l servicenames.js -l xpctest.js -o "${output}/sandbox_result.log"
```

and type in `evaluate_sandbox()` and exit afterwards.

2. In another tab, deactivate launchd checks

```bash
frida -U -p 1 -l launchd_get_out_of_my_way.js -P '{"pid":-1}'   
```

3. Inject into empty app to get all reachable service
```bash
frida -U -f "$target" -l servicenames.js -l xpctest.js -o "${output}/no_sandbox_result.log" 
```
and type in `evaluate_sandbox()` and exit afterwards.

4. Check the log files

One should say `Launchd Sandbox bypass is OFF for process 1749` and one should say `Launchd Sandbox bypass is ON for process 1749` (irrelevant of the PID)

### Results

- `sandbox_result.log` contains default reachable service (from the perspective of the default sandbox profile)
- `no_sandbox_result.log` contains all reachable service to deduct which ones are deactivated

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
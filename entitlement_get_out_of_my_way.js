const mod = Process.getModuleByName("libSystem.B.dylib");
const xpc = Process.getModuleByName("libxpc.dylib");
const foundation = Process.getModuleByName("Foundation");


const proc_name_addr = mod.getExportByName('proc_name');
const proc_name = new NativeFunction(proc_name_addr, 'void', ['uint32', 'pointer', 'uint32']); // int pid, char *buf, int size

// utility methods

const xpc_copy_description = new NativeFunction(xpc.findExportByName( "xpc_copy_description"), 'pointer', ['pointer']);
const xpc_connection_get_pid = new NativeFunction(xpc.getExportByName("xpc_connection_get_pid"),"int",["pointer"]);
const xpc_bool_get_value = new NativeFunction(xpc.findExportByName( "xpc_bool_get_value"),'bool', ['pointer']);
const xpc_bool_create = new NativeFunction(xpc.findExportByName( "xpc_bool_create"),'pointer', ['bool']);
const free = new NativeFunction(mod.findExportByName( "free"), 'void', ['pointer']);

// entitlement methods
// we leave out xpc_copy_event_entitlements.js
const xpc_connection_copy_entitlement_value = new NativeFunction(
	xpc.getExportByName("xpc_connection_copy_entitlement_value"),"pointer",["pointer","pointer"]
);
// const xpc_connection_has_entitlement = new NativeFunction(
// 	xpc.getExportByName("xpc_connection_has_entitlement"),"pointer",["pointer","pointer"]
// );

// (key) -> __xpc_copy_entitlements_data
const xpc_copy_entitlement_for_self = new NativeFunction(
	xpc.getExportByName("xpc_copy_entitlement_for_self"),
	"pointer",
	["pointer"]
)
// () -> __xpc_copy_entitlements_data
const xpc_copy_entitlements_for_self = new NativeFunction(
	xpc.getExportByName("xpc_copy_entitlements_for_self"),
	"pointer",
	[]
)
// (ent,token) -> __xpc_copy_entitlements_data
const xpc_copy_entitlement_for_token = new NativeFunction(
	xpc.getExportByName("xpc_copy_entitlement_for_token"),
	"pointer",
	["pointer","pointer"]
)
// (token) -> __xpc_copy_entitlements_data
const xpc_copy_entitlements_data_for_token = new NativeFunction(
	xpc.getExportByName("xpc_copy_entitlements_data_for_token"),
	"pointer",
	["pointer"]
)
// (pid) -> __xpc_copy_entitlements_data
const xpc_copy_entitlements_for_pid = new NativeFunction(
	xpc.getExportByName("xpc_copy_entitlements_for_pid"),
	"pointer",
	["pointer"]
)

/*
	We cannot use Interceptor.replace as the native callback assumes a fixed number of arguments :/ 
	Sandbox function has varargs ...
*/

var target_pid;
var verbose;

// https://github.com/frida/frida/issues/2818
rpc.exports = {
    init(stage, parameters) {
		target_pid = parameters.pid ?? -1;
		verbose = parameters.verbose ?? false;
		console.log(`Modifying for ${target_pid < 0 ? "everything" : target_pid}`);
    },
};


// Interceptor.attach(xpc_connection_has_entitlement, {
// 	onEnter(args) {
// 		let pid = xpc_connection_get_pid(args[0]);
// 		let entitlement = args[1].readCString();

// 		this.shouldBypass = target_pid < 0 || target_pid == arg_pid;
// 		if(!verbose){
// 			return;
// 		}

// 		let mem = Memory.alloc(0x100);
// 		proc_name(pid, mem, 0x100);
// 		let pid_name = mem.readCString();

// 		this.current_log = `xpc_connection_has_entitlement(${pid_name}(${pid}), ent: ${entitlement})`;
// 	},
// 	onLeave(retval) {
// 		if(verbose && this.current_log){
// 			let description = retval.isNull() ? "nil" : xpc_copy_description(retval).readCString();
// 			console.log(this.current_log + " => " + description);
// 			this.current_log = "";
// 		}
// 		// if (this.shouldBypass) {
// 		//     retval.replace(xpc_bool_create(1)); 
// 		// }
// 	}
// });

Interceptor.attach(xpc_connection_copy_entitlement_value, {
	onEnter(args) {
		let pid = xpc_connection_get_pid(args[0]);
		let entitlement = args[1].readCString();

		this.shouldBypass = target_pid < 0 || target_pid == arg_pid;
		if(!verbose){
			return;
		}

		let mem = Memory.alloc(0x100);
		proc_name(pid, mem, 0x100);
		let pid_name = mem.readCString();
	
		this.current_log = `xpc_connection_copy_entitlement_value(${pid_name}(${pid}), ent: ${entitlement})`;

	},
	onLeave(retval) {
		if(verbose && this.current_log){
			let description = retval.isNull() ? "nil" : xpc_copy_description(retval).readCString();
			console.log(this.current_log + " => " + description);
			this.current_log = "";
		}
        // if (this.shouldBypass) {
        //     retval.replace(xpc_bool_create(1)); 
        // }
	}
});

Interceptor.attach(xpc_copy_entitlement_for_self, {
	onEnter(args) {
		let pid = Process.id;
		let entitlement = args[0].readCString();

		this.shouldBypass = target_pid < 0 || target_pid == arg_pid;
		if(!verbose){
			return;
		}

		let mem = Memory.alloc(0x100);
		proc_name(pid, mem, 0x100);
		let pid_name = mem.readCString();
	
		this.current_log = `xpc_copy_entitlement_for_self(${pid_name}(${pid}), ent: ${entitlement})`;

	},
	onLeave(retval) {
		if(verbose && this.current_log){
			let description = retval.isNull() ? "nil" : xpc_copy_description(retval).readCString();
			console.log(this.current_log + " => " + description);
			this.current_log = "";
		}
	}
});

Interceptor.attach(xpc_copy_entitlements_for_self, {
	onEnter(args) {
		let pid = Process.id;

		this.shouldBypass = target_pid < 0 || target_pid == arg_pid;
		if(!verbose){
			return;
		}

		let mem = Memory.alloc(0x100);
		proc_name(pid, mem, 0x100);
		let pid_name = mem.readCString();
	
		this.current_log = `xpc_copy_entitlements_for_self(${pid_name}(${pid}), ent: ${entitlement})`;

	},
	onLeave(retval) {
		if(verbose && this.current_log){
			let description = retval.isNull() ? "nil" : xpc_copy_description(retval).readCString();
			console.log(this.current_log + " => " + description);
			this.current_log = "";
		}
	}
});

Interceptor.attach(xpc_copy_entitlement_for_token, {
	onEnter(args) {
		let entitlement = args[0].readCString();
		let pid = Process.id;

		if(args[1].readU32() != 0){
			pid = args[1].add(5*4).readU32();
		}

		this.shouldBypass = target_pid < 0 || target_pid == arg_pid;
		if(!verbose){
			return;
		}

		let mem = Memory.alloc(0x100);
		proc_name(pid, mem, 0x100);
		let pid_name = mem.readCString();
	
		this.current_log = `xpc_copy_entitlement_for_token(${pid_name}(${pid}), ent: ${entitlement})`;

	},
	onLeave(retval) {
		if(verbose && this.current_log){
			let description = retval.isNull() ? "nil" : xpc_copy_description(retval).readCString();
			console.log(this.current_log + " => " + description);
			this.current_log = "";
		}
	}
});

Interceptor.attach(xpc_copy_entitlements_for_self, {
	onEnter(args) {
		let pid = Process.id;

		this.shouldBypass = target_pid < 0 || target_pid == arg_pid;
		if(!verbose){
			return;
		}

		let mem = Memory.alloc(0x100);
		proc_name(pid, mem, 0x100);
		let pid_name = mem.readCString();
	
		this.current_log = `xpc_copy_entitlements_for_self(${pid_name}(${pid}), ent: ${entitlement})`;
	},
	onLeave(retval) {
		if(verbose && this.current_log){
			let description = retval.isNull() ? "nil" : xpc_copy_description(retval).readCString();
			console.log(this.current_log + " => " + description);
			this.current_log = "";
		}
	}
});

Interceptor.attach(xpc_copy_entitlements_for_pid, {
	onEnter(args) {
		let pid = args[0].readU32();

		this.shouldBypass = target_pid < 0 || target_pid == arg_pid;
		if(!verbose){
			return;
		}

		let mem = Memory.alloc(0x100);
		proc_name(pid, mem, 0x100);
		let pid_name = mem.readCString();
	
		this.current_log = `xpc_copy_entitlements_for_pid(${pid_name}(${pid}), ent: ${entitlement})`;
	},
	onLeave(retval) {
		if(verbose && this.current_log){
			let description = retval.isNull() ? "nil" : xpc_copy_description(retval).readCString();
			console.log(this.current_log + " => " + description);
			this.current_log = "";
		}
	}
});

Interceptor.attach(xpc_copy_entitlements_data_for_token, {
	onEnter(args) {
		let entitlement = args[0].readCString();
		let pid = Process.id;

		if(args[1].readU32() != 0){
			pid = args[1].add(5*4).readU32();
		}

		this.shouldBypass = target_pid < 0 || target_pid == arg_pid;
		if(!verbose){
			return;
		}

		let mem = Memory.alloc(0x100);
		proc_name(pid, mem, 0x100);
		let pid_name = mem.readCString();
		this.current_log = `xpc_copy_entitlements_data_for_token(${pid_name}(${pid}), ent: ${entitlement})`;

	},
	onLeave(retval) {
		if(verbose && this.current_log){
			let description = retval.isNull() ? "nil" : xpc_copy_description(retval).readCString();
			console.log(this.current_log + "=> " + description);
			this.current_log = "";
		}
	}
});


// CFTypeRef SecTaskCopyValueForEntitlement(SecTaskRef task, CFStringRef entitlement, CFErrorRef * error);
// CFDictionaryRef SecTaskCopyValuesForEntitlements(SecTaskRef task, CFArrayRef entitlements, CFErrorRef * error);

// const SecTaskCopyValueForEntitlement = new NativeFunction(
// 	Module.getExportByName(null,"SecTaskCopyValueForEntitlement"),
// 	"pointer",
// 	["pointer","pointer","pointer"]
// )
// const SecTaskCopyValuesForEntitlements = new NativeFunction(
// 	Module.getExportByName(null,"SecTaskCopyValuesForEntitlements"),
// 	"pointer",
// 	["pointer","pointer","pointer"]
// )
		


var supported_secTask = [] 

if (foundation.findExportByName("SecTaskCopyValueForEntitlement")){
	supported_secTask.push("SecTaskCopyValueForEntitlement")
	console.log("Registered SecTaskCopyValueForEntitlement")
}

if (foundation.findExportByName("SecTaskCopyValuesForEntitlements")){
	supported_secTask.push("SecTaskCopyValuesForEntitlements")
	console.log("Registered SecTaskCopyValuesForEntitlements")
}

/*
According to

https://chromium.googlesource.com/chromium/src/+/refs/tags/124.0.6367.18/crypto/apple_keychain_v2.h

#if !BUILDFLAG(IS_IOS)
  // TaskCopyValueForEntitlement wraps the |SecTaskCopyValueForEntitlement|
  // function. Not available on iOS.
  virtual base::apple::ScopedCFTypeRef<CFTypeRef> TaskCopyValueForEntitlement(
      SecTaskRef task,
      CFStringRef entitlement,
      CFErrorRef* error);
#endif  // !BUILDFLAG(IS_IOS)

But we can still get it via the foundation one; found via:

Process.enumerateModules().forEach(function(module) {
    // Check if the module exports 'SecTaskCopyValueForEntitlement'
    var ex = module.findExportByName('SecTaskCopyValueForEntitlement');
    if (ex) {
        console.log('Found SecTaskCopyValueForEntitlement in:', module.name);
    }
});
*/

supported_secTask.forEach(function(fun_name){
	const nfunc = new NativeFunction(
		foundation.getExportByName(fun_name),
		"pointer",
		["pointer","pointer","pointer"]
	);
	Interceptor.attach(nfunc, {
		onEnter(args) {

			if(!verbose){
				return;
			}

			var ents = ObjC.Object(args[1]).toString();
			this.current_log = `${fun_name}(task: ${args[0]}, ent: ${ents}, err: ${args[2]})`;
		},
		onLeave(retval) {
			if(verbose && this.current_log){
				console.log(this.current_log + " => " + (ObjC.Object(retval).toString()));
				this.current_log = "";
			}
		}
	});
});

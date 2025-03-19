const sandbox_check_by_audit_token_addr = Module.getExportByName(null, 'sandbox_check_by_audit_token');
const sandbox_check = Module.getExportByName(null, 'sandbox_check');

const proc_name_addr = Module.getExportByName(null, 'proc_name');
															// int pid, char *buf, int size
const proc_name = new NativeFunction(proc_name_addr, 'void', ['uint32', 'pointer', 'uint32']); 
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
		console.log(`Modifying launchd for ${target_pid < 0 ? "everything" : target_pid}`);
    },
};

const FLAG_TO_SANDBOX_FILTER = {
	2: "global-name",
	12: "xpc-service-name"
}

// sandbox_check_by_audit_token(pid:${pid}, type:${type}, op:${op}, args:${vargs})`
Interceptor.attach(sandbox_check_by_audit_token_addr, {
	onEnter(args) {
		// pid is the 5th element in the audit_token(uint32[8])
		let arg_pid = args[0].add(5*4).readU32();
		let arg_op = args[1].readCString();
		let arg_type = args[2].toInt32();

		if(!arg_op || !arg_op.includes("mach")){
			return;
		}
		// state
		this.shouldBypass = target_pid < 0 || target_pid == arg_pid;
		if(!verbose){
			return;
		}
		let mem = Memory.alloc(0x100);
		proc_name(arg_pid, mem, 0x100);
		let pid_name = mem.readCString();
		let service_name = args[3].readCString();
		
		let flag;
		if(arg_type in FLAG_TO_SANDBOX_FILTER){
			flag = FLAG_TO_SANDBOX_FILTER[arg_type];
		}else{
			flag = `Unknown(${arg_type})`;
		}

		this.current_log = `${pid_name}(${arg_pid}): ${arg_op}(${flag}) -> ${service_name}`
	},
	onLeave(retval) {
		if(verbose && this.current_log){
			console.log(this.current_log + " => " + (retval.toInt32() ? "DENY" : "ACCEPT"));
			this.current_log = "";
		}
        if (this.shouldBypass) {
            retval.replace(0); 
        }
	}
});
fn main() {
    let this_pid = std::process::id();

    println!("Process {this_pid} before singleton process.");

    std::mem::forget(singleton_process::SingletonProcess::try_new(None, true).unwrap());

    println!("Process {this_pid} after singleton process. Try to spawn another process now ...");

    std::thread::sleep(std::time::Duration::from_secs(10));

    println!("Process {this_pid} terminates gracefully.");
}

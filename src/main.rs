use clap::Parser;

#[derive(Parser)]
struct Opt {
    dir: String,
}

fn main() {
    let o = Opt::parse();
    let v = skylos::analyze_dir(&o.dir).unwrap();
    println!("{}", serde_json::to_string_pretty(&v).unwrap());
}

struct TextCodec;

impl TextCodec {
    fn process(&self) -> u32 {
        self.measure()
    }

    fn measure(&self) -> u32 {
        1
    }

    fn snapshot(&self) -> u32 {
        2
    }
}

struct BinaryCodec;

impl BinaryCodec {
    fn process(&self) -> u32 {
        3
    }
}

fn main() {
    let text = TextCodec;
    let _ = BinaryCodec;
    println!("{}", text.process());
}

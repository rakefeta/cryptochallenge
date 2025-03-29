fn norm_ham_dist0(s1: &str, s2: &str) -> f64 {
    assert_eq!(s1.len(), s2.len());
    let sb = s1.as_bytes();
    let sbi: Vec<String> = sb.iter().map(|x| format!("{x:08b}")).collect();
    let sbi = sbi.join("");

    let tb = s2.as_bytes();
    let tbi: Vec<String> = tb.iter().map(|x| format!("{x:08b}")).collect();
    let tbi = tbi.join("");

    // println!("{:?}", sbi);
    // println!("{:?}", tbi);

    let mut hd = 0;

    for (s, t) in sbi.chars().zip(tbi.chars()) {
        if s != t {
            hd += 1
        }
    }
    // println!("DITANCE = {:?}", hd);
    f64::from(hd) / f64::from(s1.len() as u8)
}

fn norm_ham_dist(s1: &str, s2: &str) -> f32 {
    assert_eq!(s1.len(), s2.len());
    let mut hd: usize = 0;
    for (b1, b2) in s1.as_bytes().iter().zip(s2.as_bytes().iter()) {
        hd += (b1^b2).count_ones() as usize;
    }

    (hd as f32) / (s1.len() as f32)
}

fn main() {
    let s = "HUIfTQsPAh9PE048GmllH0kcDk4TAQsHThsBFkU2AB4BSWQgVB0dQzNTTmVS";
    let mut hdmin: f32 = f32::MAX;
    let mut ksmin: usize = 0;
    for ks in 2..=25 {
        let ch1 = &s[0..ks];
        let ch2 = &s[ks..2*ks];
        let mut hd: usize = 0;
        for (b1, b2) in ch1.as_bytes().iter().zip(ch2.as_bytes().iter()) {
            hd += (b1^b2).count_ones() as usize;
        };
        let hd_norm = (hd as f32) / (ks as f32);
        // let hd_norm = norm_ham_dist(ch1, ch2);
        if hd_norm < hdmin {
            hdmin = hd_norm;
            ksmin = ks
        }
        println!("KEYSIZE({:?}): HD({:?}): {:?}", ks, hd, (hd as f32) / (ks as f32));
    }
    println!("HDMIN = {:?}", hdmin);
    println!("KSMIN = {:?}", ksmin);
}

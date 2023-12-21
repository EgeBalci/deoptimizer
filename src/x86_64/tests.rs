#[cfg(test)]
mod tests {
    use crate::x86_64::*;
    use iced_x86::*;

    #[test]
    fn test_ap_transform() {
        let code_64: &[u8] = &[
            0xbf, 0x8e, 0x00, 0x00, 0xc0, 0x41, 0xb9, 0x02, 0x00, 0x00, 0x00, 0xc6, 0x40, 0x38,
            0x01, 0x48, 0xb8, 0xf0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x04, 0x10, 0x81,
            0xc2, 0x02, 0x10, 0x00, 0x00, 0x48, 0x81, 0xc6, 0x10, 0xff, 0xff, 0xff, 0x81, 0xd6,
            0x0c, 0x00, 0x88, 0xd6, 0x48, 0x81, 0xd6, 0x0c, 0x00, 0x88, 0x00, 0x14, 0xdc, 0x2c,
            0xa0, 0x48, 0x81, 0xee, 0xa0, 0x00, 0x00, 0x00, 0x2d, 0x20, 0x05, 0x93, 0x19, 0x1c,
            0x0c, 0x48, 0x1d, 0x33, 0x11, 0x22, 0x00,
        ];
        let code_32: &[u8] = &[
            0xbf, 0x8e, 0x00, 0x00, 0xc0, 0xbe, 0x77, 0x73, 0x32, 0x5f, 0xb8, 0x02, 0x00, 0x00,
            0x00, 0xc6, 0x80, 0x90, 0x00, 0x00, 0x00, 0x01, 0xbb, 0xff, 0xff, 0xff, 0xff, 0x04,
            0x10, 0x81, 0xc2, 0x02, 0x10, 0x00, 0x00, 0x81, 0xd6, 0x0c, 0x00, 0x88, 0xd6, 0x14,
            0xdc, 0x81, 0xee, 0xa0, 0x00, 0x00, 0x00, 0x2d, 0x44, 0x33, 0x22, 0x11, 0x1c, 0xcc,
            0x83, 0xdc, 0x10,
        ];
        let mut decoder64 = Decoder::new(64, code_64, DecoderOptions::NONE);
        let mut decoder32 = Decoder::new(32, code_32, DecoderOptions::NONE);
        let mut inst = Instruction::default();
        println!("\n[=========== Testing x64 AP Transform ===========]");
        while decoder64.can_decode() {
            decoder64.decode_out(&mut inst);
            println!("[>] {}", inst);
            match apply_ap_transform(64, &mut inst.clone()) {
                Ok(result) => {
                    for i in result {
                        println!("{:016X}:\t{}", i.ip(), i);
                    }
                }
                Err(e) => {
                    println!("[-] {e}");
                    assert!(false);
                }
            };
        }

        println!("\n[=========== Testing x86 AP Transform ===========]");
        while decoder32.can_decode() {
            decoder32.decode_out(&mut inst);
            println!("[>] {}", inst);
            match apply_ap_transform(32, &mut inst.clone()) {
                Ok(result) => {
                    for i in result {
                        println!("{:016X}:\t{}", i.ip(), i);
                    }
                }
                Err(e) => {
                    println!("[-] {e}");
                    assert!(false);
                }
            };
        }
    }

    #[test]
    fn test_li_transform() {
        println!("[*] Testing logical inverse transform...");
        let code_64: &[u8] = &[
            0x41, 0x81, 0xf2, 0x69, 0x6e, 0x65, 0x49, 0x34, 0x01, 0x80, 0x74, 0x24, 0x27, 0x01,
            0x24, 0x01, 0x25, 0x00, 0x00, 0x08, 0x00, 0x48, 0x81, 0x23, 0xff, 0x9f, 0xff, 0xff,
            0x81, 0x20, 0x1f, 0x00, 0xfe, 0xff, 0x80, 0x64, 0xf8, 0x38, 0xfb, 0x81, 0xca, 0x00,
            0x03, 0x00, 0x00, 0x81, 0xca, 0x00, 0x00, 0x00, 0x03, 0x48, 0x81, 0x0b, 0x00, 0x60,
            0x00, 0x00, 0x80, 0x4c, 0xc8, 0x38, 0x20,
        ];
        let code_32: &[u8] = &[
            0x81, 0xf1, 0x69, 0x6e, 0x65, 0x49, 0x34, 0x01, 0x80, 0x74, 0x24, 0x27, 0x01, 0x24,
            0x01, 0x25, 0x00, 0x00, 0x08, 0x00, 0x83, 0x23, 0xff, 0x81, 0x20, 0x1f, 0x00, 0xfe,
            0xff, 0x80, 0x64, 0xf8, 0x38, 0xfb, 0x81, 0xca, 0x00, 0x03, 0x00, 0x00, 0x81, 0xca,
            0x00, 0x00, 0x00, 0x03, 0x81, 0x0b, 0x00, 0x60, 0x00, 0x00, 0x80, 0x4c, 0xc8, 0x38,
            0x20,
        ];
        let mut decoder64 = Decoder::new(64, code_64, DecoderOptions::NONE);
        let mut decoder32 = Decoder::new(32, code_32, DecoderOptions::NONE);
        let mut inst = Instruction::default();
        println!("\n[=========== Testing x64 LI Transform ===========]");
        while decoder64.can_decode() {
            decoder64.decode_out(&mut inst);
            println!("[>] {}", inst);
            match apply_li_transform(64, &mut inst.clone()) {
                Ok(result) => {
                    for i in result {
                        println!("{:016X}:\t{}", i.ip(), i);
                    }
                }
                Err(e) => {
                    println!("[-] {e}");
                    assert!(false);
                }
            };
        }

        println!("\n[=========== Testing x86 LI Transform ===========]");
        while decoder32.can_decode() {
            decoder32.decode_out(&mut inst);
            println!("[>] {}", inst);
            match apply_li_transform(32, &mut inst.clone()) {
                Ok(result) => {
                    for i in result {
                        println!("{:016X}:\t{}", i.ip(), i);
                    }
                }
                Err(e) => {
                    println!("[-] {e}");
                    assert!(false);
                }
            };
        }
    }

    #[test]
    fn test_lp_transform() {
        println!("[*] Testing logical partitioning transform...");
        let code_64: &[u8] = &[
            0x48, 0xd1, 0xeb, 0xd0, 0xe0, 0x66, 0xd1, 0xf8, 0xd1, 0xe1, 0x48, 0xc1, 0xeb, 0x00,
            0x48, 0xc1, 0xeb, 0x10, 0xc0, 0xe0, 0x05, 0x67, 0x48, 0xc1, 0x21, 0x20, 0xc1, 0xc8,
            0x0a, 0xc0, 0x0a, 0x14, 0x48, 0xc1, 0xc1, 0x31, 0xc1, 0xc6, 0x69,
        ];
        let code_32: &[u8] = &[
            0xd1, 0xeb, 0xd0, 0xe0, 0x66, 0xd1, 0xf8, 0xd1, 0xe1, 0xc1, 0xeb, 0x00, 0xc1, 0xeb,
            0x10, 0xc0, 0xe0, 0x05, 0xc1, 0x21, 0x20, 0xc1, 0xc8, 0x0a, 0xc0, 0x0a, 0x14, 0xc1,
            0xc1, 0x31, 0xc1, 0xc6, 0x69,
        ];
        let mut decoder64 = Decoder::new(64, code_64, DecoderOptions::NONE);
        let mut decoder32 = Decoder::new(32, code_32, DecoderOptions::NONE);
        let mut inst = Instruction::default();
        println!("\n[=========== Testing x64 LP Transform ===========]");
        while decoder64.can_decode() {
            decoder64.decode_out(&mut inst);
            println!("[>] {}", inst);
            match apply_lp_transform(64, &mut inst.clone()) {
                Ok(result) => {
                    for i in result {
                        println!("{:016X}:\t{}", i.ip(), i);
                    }
                }
                Err(e) => {
                    println!("[-] {e}");
                    assert!(false);
                }
            };
        }

        println!("\n[=========== Testing x86 LP Transform ===========]");
        while decoder32.can_decode() {
            decoder32.decode_out(&mut inst);
            println!("[>] {}", inst);
            match apply_lp_transform(32, &mut inst.clone()) {
                Ok(result) => {
                    for i in result {
                        println!("{:016X}:\t{}", i.ip(), i);
                    }
                }
                Err(e) => {
                    println!("[-] {e}");
                    assert!(false);
                }
            };
        }
    }
    #[test]
    fn test_itr_transform() {
        println!("[*] Testing immediate to register transform...");
        let code_64: &[u8] = &[
            0x41, 0x81, 0xf2, 0x69, 0x6e, 0x65, 0x49, 0x34, 0x01, 0x80, 0x74, 0x24, 0x27, 0x01,
            0x24, 0x01, 0x25, 0x00, 0x00, 0x08, 0x00, 0x48, 0x81, 0x23, 0xff, 0x9f, 0xff, 0xff,
            0x81, 0x20, 0x1f, 0x00, 0xfe, 0xff, 0x80, 0x64, 0xf8, 0x38, 0xfb, 0x81, 0xca, 0x00,
            0x03, 0x00, 0x00, 0x81, 0xca, 0x00, 0x00, 0x00, 0x03, 0x48, 0x81, 0x0b, 0x00, 0x60,
            0x00, 0x00, 0x80, 0x4c, 0xc8, 0x38, 0x20, 0xd1, 0xeb, 0xc1, 0xeb, 0x00, 0x48, 0xc1,
            0xeb, 0x10, 0xc0, 0xe0, 0x05, 0xc1, 0x21, 0x20, 0xc1, 0xc8, 0x0a, 0xc0, 0x0a, 0x14,
            0x48, 0xc1, 0xc1, 0x31, 0x40, 0xc0, 0xc6, 0x69,
        ];
        let code_32: &[u8] = &[
            0x81, 0xf2, 0x69, 0x6e, 0x65, 0x49, 0x34, 0x01, 0x80, 0x74, 0x24, 0x27, 0x01, 0x24,
            0x01, 0x25, 0x00, 0x00, 0x08, 0x00, 0x83, 0x23, 0xff, 0x81, 0x20, 0x1f, 0x00, 0xfe,
            0xff, 0x80, 0x64, 0xf8, 0x38, 0xfb, 0x81, 0xca, 0x00, 0x03, 0x00, 0x00, 0x81, 0xca,
            0x00, 0x00, 0x00, 0x03, 0x81, 0x0b, 0x00, 0x60, 0x00, 0x00, 0x80, 0x4c, 0xc8, 0x38,
            0x20, 0xd1, 0xeb, 0xc1, 0xeb, 0x00, 0xc1, 0xeb, 0x10, 0xc0, 0xe0, 0x05, 0xc1, 0x21,
            0x20, 0xc1, 0xc8, 0x0a, 0xc0, 0x0a, 0x14, 0xc1, 0xc1, 0x31, 0xc1, 0xc6, 0x69,
        ];
        let mut decoder64 = Decoder::new(64, code_64, DecoderOptions::NONE);
        let mut decoder32 = Decoder::new(32, code_32, DecoderOptions::NONE);
        let mut inst = Instruction::default();
        println!("\n[=========== Testing x64 ITR Transform ===========]");
        while decoder64.can_decode() {
            decoder64.decode_out(&mut inst);
            println!("[>] {}", inst);
            match apply_itr_transform(64, &mut inst.clone()) {
                Ok(result) => {
                    for i in result {
                        println!("{:016X}:\t{}", i.ip(), i);
                    }
                }
                Err(e) => {
                    println!("[-] {e}");
                    assert!(false);
                }
            };
        }

        println!("\n[=========== Testing x86 ITR Transform ===========]");
        while decoder32.can_decode() {
            decoder32.decode_out(&mut inst);
            println!("[>] {}", inst);
            match apply_itr_transform(32, &mut inst.clone()) {
                Ok(result) => {
                    for i in result {
                        println!("{:016X}:\t{}", i.ip(), i);
                    }
                }
                Err(e) => {
                    println!("[-] {e}");
                    assert!(false);
                }
            };
        }
    }

    #[test]
    fn test_om_transform() {
        println!("[*] testing offset mutation...");
        let code_64: &[u8] = &[
            0x48, 0x8d, 0x09, 0x89, 0x38, 0x48, 0x8b, 0x4b, 0x28, 0x48, 0x89, 0x74, 0x24, 0x10,
            0xc7, 0x45, 0x40, 0x01, 0x00, 0x00, 0x00, 0x48, 0x89, 0x54, 0xc8, 0x28, 0x48, 0x8d,
            0x0c, 0xc9, 0x41, 0x0f, 0xb6, 0xb4, 0x80, 0x53, 0xb3, 0x0f, 0x00, 0x48, 0x81, 0x23,
            0xff, 0x9f, 0xff, 0xff, 0x48, 0x0f, 0xba, 0x2b, 0x0e, 0x48, 0x8b, 0x04, 0x25, 0x88,
            0x77, 0x66, 0x55,
        ];
        let code_32: &[u8] = &[
            0x8d, 0x09, 0x89, 0x38, 0x8b, 0x4b, 0x28, 0x8b, 0x4b, 0xd8, 0x89, 0x74, 0x24, 0x10,
            0xc7, 0x45, 0x40, 0x01, 0x00, 0x00, 0x00, 0x89, 0x54, 0xc8, 0x28, 0x89, 0x54, 0xc8,
            0xd8, 0x8d, 0x0c, 0xc9, 0x0f, 0xb6, 0xb4, 0x81, 0x53, 0xb3, 0x0f, 0x00, 0x83, 0x23,
            0xff, 0x0f, 0xba, 0x2b, 0x0e, 0xa1, 0x88, 0x77, 0x66, 0x55,
        ];
        let mut decoder64 = Decoder::new(64, code_64, DecoderOptions::NONE);
        let mut decoder32 = Decoder::new(32, code_32, DecoderOptions::NONE);
        let mut inst = Instruction::default();
        println!("\n[=========== Testing x64 OM Transform ===========]");
        while decoder64.can_decode() {
            decoder64.decode_out(&mut inst);
            println!("[>] {}", inst);
            match apply_om_transform(64, &mut inst.clone()) {
                Ok(result) => {
                    for i in result {
                        println!("{:016X}:\t{}", i.ip(), i);
                    }
                }
                Err(e) => {
                    println!("[-] {e}");
                    assert!(false);
                }
            };
        }

        println!("\n[=========== Testing x86 OM Transform ===========]");
        while decoder32.can_decode() {
            decoder32.decode_out(&mut inst);
            println!("[>] {}", inst);
            match apply_om_transform(32, &mut inst.clone()) {
                Ok(result) => {
                    for i in result {
                        println!("{:016X}:\t{}", i.ip(), i);
                    }
                }
                Err(e) => {
                    println!("[-] {e}");
                    assert!(false);
                }
            };
        }
    }

    #[test]
    fn test_rs_transform() {
        println!("[*] Testing register swap...");
        let code_64: &[u8] = &[
            0x34, 0x01, 0x66, 0x83, 0xe0, 0x31, 0x83, 0xc0, 0x69, 0x49, 0x81, 0xf2, 0x69, 0x6e,
            0x65, 0x49, 0x30, 0x44, 0x24, 0x27, 0x29, 0x5c, 0x78, 0x2a, 0x09, 0xca, 0x87, 0xd6,
        ];
        let code_32: &[u8] = &[
            0x34, 0x01, 0x66, 0x83, 0xe0, 0x31, 0x83, 0xc0, 0x69, 0x81, 0xf2, 0x69, 0x6e, 0x65,
            0x49, 0x30, 0x44, 0x24, 0x27, 0x29, 0x5c, 0x78, 0x2a, 0x09, 0xca, 0x87, 0xd6,
        ];
        let mut decoder64 = Decoder::new(64, code_64, DecoderOptions::NONE);
        let mut decoder32 = Decoder::new(32, code_32, DecoderOptions::NONE);
        let mut inst = Instruction::default();
        println!("\n[=========== Testing x64 RS Transform ===========]");
        while decoder64.can_decode() {
            decoder64.decode_out(&mut inst);
            println!("[>] {}", inst);
            match apply_rs_transform(64, &mut inst.clone()) {
                Ok(result) => {
                    for i in result {
                        println!("{:016X}:\t{}", i.ip(), i);
                    }
                }
                Err(e) => {
                    println!("[-] {e}");
                    assert!(false);
                }
            };
        }

        println!("\n[=========== Testing x86 RS Transform ===========]");
        while decoder32.can_decode() {
            decoder32.decode_out(&mut inst);
            println!("[>] {}", inst);
            match apply_rs_transform(32, &mut inst.clone()) {
                Ok(result) => {
                    for i in result {
                        println!("{:016X}:\t{}", i.ip(), i);
                    }
                }
                Err(e) => {
                    println!("[-] {e}");
                    assert!(false);
                }
            };
        }
    }

    #[test]
    fn test_get_random_gp_register() {
        match get_random_gp_register(false, 4, None) {
            Ok(reg) => assert_eq!(reg.size(), 4),
            Err(e) => println!("[-] {e}"),
        };
    }

    #[test]
    fn test_get_code_with_str() {
        assert_eq!(get_code_with_str("Add_rm32_imm8"), Code::Add_rm32_imm8)
    }
}

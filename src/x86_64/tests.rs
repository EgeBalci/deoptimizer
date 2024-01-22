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
            0x83, 0xdc, 0x10, 0x6a, 0x01, 0x68, 0xbb, 0xaa, 0x00, 0x00, 0x68, 0xdd, 0xcc, 0xbb,
            0xaa,
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
            0x48, 0x8b, 0x00, 0x48, 0x8b, 0x40, 0x10, 0x48, 0x8b, 0x40, 0xf0, 0x48, 0x8d, 0x09,
            0x89, 0x38, 0x48, 0x8b, 0x4b, 0x28, 0x48, 0x89, 0x74, 0x24, 0x10, 0xc7, 0x45, 0x40,
            0x01, 0x00, 0x00, 0x00, 0x48, 0x89, 0x54, 0xc8, 0x28, 0x48, 0x8d, 0x0c, 0xc9, 0x41,
            0x0f, 0xb6, 0xb4, 0x80, 0x53, 0xb3, 0x0f, 0x00, 0x48, 0x81, 0x23, 0xff, 0x9f, 0xff,
            0xff, 0x48, 0x0f, 0xba, 0x2b, 0x0e,
        ];
        let code_32: &[u8] = &[
            0x8b, 0x00, 0x8b, 0x40, 0x10, 0x8b, 0x40, 0xf0, 0x8d, 0x09, 0x66, 0x89, 0x10, 0x8b,
            0x4b, 0x28, 0x8b, 0x93, 0xef, 0xfe, 0xff, 0xff, 0x89, 0x74, 0x24, 0x10, 0xc7, 0x45,
            0x40, 0x01, 0x00, 0x00, 0x00, 0x89, 0x54, 0xc8, 0x28, 0x8d, 0x0c, 0xc9, 0x0f, 0xb6,
            0xb4, 0x81, 0x53, 0xb3, 0x0f, 0x00, 0x81, 0x23, 0xff, 0x9f, 0xff, 0xff, 0x0f, 0xba,
            0x2b, 0x0e,
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
            0x80, 0xf3, 0x01, 0x66, 0x83, 0xe3, 0x31, 0x83, 0xc3, 0x69, 0x49, 0x81, 0xf2, 0x69,
            0x6e, 0x65, 0x49, 0x30, 0x44, 0x24, 0x27, 0x29, 0x5c, 0x78, 0x2a, 0x09, 0xca, 0x87,
            0xd6,
        ];
        let code_32: &[u8] = &[
            0x80, 0xf3, 0x01, 0x66, 0x83, 0xe3, 0x31, 0x83, 0xc3, 0x69, 0x81, 0xf2, 0x69, 0x6e,
            0x65, 0x49, 0x30, 0x44, 0x24, 0x27, 0x29, 0x5c, 0x78, 0x2a, 0x09, 0xca, 0x87, 0xd6,
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
    fn test_extended_rencode() {
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
        println!("\n[=========== Testing x64 Transpose Transform ===========]");
        while decoder64.can_decode() {
            decoder64.decode_out(&mut inst);
            if !is_using_fixed_register(&inst) {
                continue;
            }
            println!(
                "[>] {} ({:X?})",
                inst,
                get_instruction_bytes(64, [inst].to_vec()).expect("can't decode instruction bytes")
            );
            match transpose_fixed_register_operand(&mut inst) {
                Ok(()) => println!(
                    "[+] {} ({:X?})",
                    inst,
                    get_instruction_bytes(64, [inst].to_vec())
                        .expect("can't decode instruction bytes")
                ),
                Err(e) => {
                    println!("[-] {e}");
                    assert!(false);
                }
            }
        }

        println!("\n[=========== Testing x86 AP Transform ===========]");
        while decoder32.can_decode() {
            decoder32.decode_out(&mut inst);
            if !is_using_fixed_register(&inst) {
                continue;
            }
            println!(
                "[>] {} ({:X?})",
                inst,
                get_instruction_bytes(32, [inst].to_vec()).expect("can't decode instruction bytes")
            );
            match transpose_fixed_register_operand(&mut inst) {
                Ok(()) => println!(
                    "[+] {} ({:X?})",
                    inst,
                    get_instruction_bytes(32, [inst].to_vec())
                        .expect("can't decode instruction bytes")
                ),
                Err(e) => {
                    println!("[-] {e}");
                    assert!(false);
                }
            }
        }
    }

    #[test]
    fn test_get_random_gp_register() {
        for _i in 0..300 {
            assert_ne!(
                get_random_gp_register(false, 4, None).expect("random register selection failed"),
                Register::ESP
            );
            assert_ne!(
                get_random_gp_register(false, 2, None).expect("random register selection failed"),
                Register::DS
            );

            assert_ne!(
                get_random_gp_register(true, 8, None).expect("random register selection failed"),
                Register::RSP
            );
        }
    }

    #[test]
    fn test_get_code_with_str() {
        assert_eq!(get_code_with_str("Add_rm32_imm8"), Code::Add_rm32_imm8)
    }

    #[test]
    fn list_3_operand() {
        let mut total = 0;
        let mut vex = 0;
        let mut xop = 0;
        for c in Code::values() {
            if c.op_code().op_count() == 3 && c.op_code().is_instruction() {
                total = total + 1;
                if format!("{:?}", c).contains("VEX") {
                    vex = vex + 1;
                    continue;
                }
                if format!("{:?}", c).contains("XOP") {
                    xop = xop + 1;
                    continue;
                }
                println!(
                    "Code: {:?} => {:?}, {:?}, {:?}",
                    c,
                    c.op_code().op0_kind(),
                    c.op_code().op1_kind(),
                    c.op_code().op2_kind()
                )
            }
        }
        println!("Vex: {vex}");
        println!("Xop: {xop}");
        println!("Total: {total}");
        println!("Legacy: {}", total - (vex + xop));
    }

    #[test]
    fn list_4_operand() {
        let mut total = 0;
        let mut vex = 0;
        let mut xop = 0;
        for c in Code::values() {
            if c.op_code().op_count() == 4 && c.op_code().is_instruction() {
                total = total + 1;
                if format!("{:?}", c).contains("VEX") {
                    vex = vex + 1;
                    continue;
                }
                if format!("{:?}", c).contains("XOP") {
                    xop = xop + 1;
                    continue;
                }
                println!(
                    "Code: {:?} => {:?}, {:?}, {:?}, {:?}",
                    c,
                    c.op_code().op0_kind(),
                    c.op_code().op1_kind(),
                    c.op_code().op2_kind(),
                    c.op_code().op3_kind()
                )
            }
        }
        println!("Vex: {vex}");
        println!("Xop: {xop}");
        println!("Total: {total}");
        println!("Legacy: {}", total - (vex + xop));
    }

    #[test]
    fn list_5_operand() {
        let mut total = 0;
        let mut vex = 0;
        let mut xop = 0;
        for c in Code::values() {
            if c.op_code().op_count() == 5 && c.op_code().is_instruction() {
                total = total + 1;
                if format!("{:?}", c).contains("VEX") {
                    vex = vex + 1;
                    continue;
                }
                if format!("{:?}", c).contains("XOP") {
                    xop = xop + 1;
                    continue;
                }
                println!(
                    "Code: {:?} => {:?}, {:?}, {:?}, {:?}, {:?}",
                    c,
                    c.op_code().op0_kind(),
                    c.op_code().op1_kind(),
                    c.op_code().op2_kind(),
                    c.op_code().op3_kind(),
                    c.op_code().op4_kind()
                )
            }
        }
        println!("Vex: {vex}");
        println!("Xop: {xop}");
        println!("Total: {total}");
        println!("Legacy: {}", total - (vex + xop));
    }

    #[test]
    fn temp() {
        let code_64: &[u8] = &[
            0x48, 0x8b, 0x00, 0x48, 0x8b, 0x40, 0x10, 0x48, 0x8b, 0x40, 0xf0, 0x48, 0x8d, 0x09,
            0x89, 0x38, 0x48, 0x8b, 0x4b, 0x28, 0x48, 0x89, 0x74, 0x24, 0x10, 0xc7, 0x45, 0x40,
            0x01, 0x00, 0x00, 0x00, 0x48, 0x89, 0x54, 0xc8, 0x28, 0x48, 0x8d, 0x0c, 0xc9, 0x41,
            0x0f, 0xb6, 0xb4, 0x80, 0x53, 0xb3, 0x0f, 0x00, 0x48, 0x81, 0x23, 0xff, 0x9f, 0xff,
            0xff, 0x48, 0x0f, 0xba, 0x2b, 0x0e,
        ];
        let code_32: &[u8] = &[
            0x68, 0xaa, 0x00, 0x00, 0x00, 0x68, 0xbb, 0xaa, 0x00, 0x00, 0x68, 0xdd, 0xcc, 0xbb,
            0xaa, 0x68, 0xff, 0xee, 0xdd, 0xcc, 0x68, 0xff, 0xff, 0x00, 0x00, 0x6a, 0xff, 0x6a,
            0xff,
        ];
        let mut decoder64 = Decoder::new(64, code_32, DecoderOptions::NONE);
        let mut decoder32 = Decoder::new(32, code_32, DecoderOptions::NONE);
        let mut inst = Instruction::default();
        let mut offset = 0;
        while decoder64.can_decode() {
            decoder64.decode_out(&mut inst);
            let mut dbs = convert_to_byte_value_instructions(
                64,
                &code_64[offset as usize..offset as usize + inst.len()],
                inst.ip(),
            )
            .expect("db convertion failed");
            // let disp_size = inst.memory_displ_size();
            // let mem_disp = inst.memory_displacement64();
            for i in dbs.iter_mut() {
                println!("[i] {} -> {:?} - ({:?})", i, i.code(), i.mnemonic());
                i.set_code(Code::DeclareByte);
                println!(">> {} -> {:?} - {:?}", i, i.code(), i.mnemonic());
            }

            offset += inst.len();
            // println!("\t--> op1_kind: {:?}", inst.op0_kind());
            // println!("\t--> mem_disp: {}", mem_disp);
            // println!("\t--> mem_disp_size: {}", disp_size);
            // println!(
            // "\t--> mem_disp_sign: {}",
            // mem_disp < u64::pow(2, disp_size * 8) / 2
            // );
        }

        println!("i32 MIN: {}", i32::MIN);
        println!("i32 MAX: {}", i32::MAX);
    }
}

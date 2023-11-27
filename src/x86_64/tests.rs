#[cfg(test)]
mod tests {
    use crate::x86_64::*;
    use iced_x86::*;

    #[test]
    fn test_om_transform() {
        println!("[*] testing offset mutation...");
        // let inst = Instruction::with2(
        //     Code::Mov_r64_rm64,
        //     Register::RAX,
        //     MemoryOperand::with_base_displ(Register::RBX, 0x10),
        // )
        let inst = Instruction::with2(
            Code::Mov_r64_rm64,
            Register::RAX,
            MemoryOperand::new(
                Register::RBX,
                Register::AL,
                1,
                0x10,
                1,
                false,
                Register::None,
            ),
        )
        .expect("Instruction creation failed");
        let mut formatter = NasmFormatter::new();
        let mut formatted_inst = String::new();
        formatter.format(&inst, &mut formatted_inst);
        println!("[*] instruction: {}", formatted_inst);
        println!("[*] Memory Base: {:?}", inst.memory_base());
        // assert_eq!(formatted_inst, "mov eax,[ebx+10h]");
        for _i in 0..10 {
            println!("---------------------");
            match apply_om_transform(&mut inst.clone(), 64) {
                Ok(result) => {
                    for i in result {
                        formatted_inst.clear();
                        formatter.format(&mut i.clone(), &mut formatted_inst);
                        println!("[+] {}", formatted_inst);
                    }
                }
                Err(e) => {
                    println!("[-] {e}");
                    break;
                }
            };
        }
    }

    #[test]
    fn test_rs_transform() {
        println!("[*] Testing register swap...");
        let inst = Instruction::with2(Code::Mov_rm64_r64, Register::RAX, Register::RBX)
            .expect("Instruction creation failed");
        let mut formatter = NasmFormatter::new();
        let mut formatted_inst = String::new();
        formatter.format(&inst, &mut formatted_inst);
        println!("[*] instruction: {}", formatted_inst);
        // assert_eq!(formatted_inst, "mov eax,bl");
        for _i in 0..10 {
            println!("---------------------");
            match apply_rs_transform(&mut inst.clone(), 64) {
                Ok(res) => {
                    for i in res {
                        formatted_inst.clear();
                        formatter.format(&mut i.clone(), &mut formatted_inst);
                        println!("[+] {}", formatted_inst);
                    }
                }
                Err(e) => {
                    println!("[-] {e}");
                    break;
                }
            }
        }
    }

    #[test]
    fn test_itr_transform() {
        println!("[*] Testing immediate to register transform...");
        let inst = Instruction::with2(Code::Mov_r32_imm32, Register::EAX, 0x6931)
            .expect("Instruction creation failed");
        let mut formatter = NasmFormatter::new();
        let mut formatted_inst = String::new();
        formatter.format(&inst, &mut formatted_inst);
        println!("[*] instruction: {}", formatted_inst);
        // assert_eq!(formatted_inst, "mov eax,ebx");
        for _i in 0..10 {
            println!("---------------------");
            match apply_itr_transform(&mut inst.clone(), 32) {
                Ok(res) => {
                    for i in res {
                        formatted_inst.clear();
                        formatter.format(&mut i.clone(), &mut formatted_inst);
                        println!("[+] {}", formatted_inst);
                    }
                }
                Err(e) => {
                    println!("[-] {e}");
                    break;
                }
            }
        }
    }

    #[test]
    fn test_ap_transform() {
        println!("[*] Testing arithmetic partitioning transform...");
        let inst = Instruction::with2(Code::Mov_rm32_imm32, Register::EAX, 0xDEADBEEF as u32)
            .expect("Instruction creation failed");
        let mut formatter = NasmFormatter::new();
        let mut formatted_inst = String::new();
        formatter.format(&inst, &mut formatted_inst);
        println!("[*] instruction: {}", formatted_inst);
        // assert_eq!(formatted_inst, "mov eax,ebx");
        for _i in 0..10 {
            println!("---------------------");
            match apply_ap_transform(&mut inst.clone()) {
                Ok(res) => {
                    for i in res {
                        formatted_inst.clear();
                        formatter.format(&mut i.clone(), &mut formatted_inst);
                        println!("[+] {}", formatted_inst);
                    }
                }
                Err(e) => {
                    println!("[-] {e}");
                    break;
                }
            }
        }
    }

    #[test]
    fn test_li_transform() {
        println!("[*] Testing logical inverse transform...");
        let inst = Instruction::with2(Code::Ror_rm32_imm8, Register::EAX, 0x31)
            .expect("Instruction creation failed");
        let mut formatter = NasmFormatter::new();
        let mut formatted_inst = String::new();
        formatter.format(&inst, &mut formatted_inst);
        println!("[*] instruction: {}", formatted_inst);
        // assert_eq!(formatted_inst, "mov eax,ebx");
        println!("---------------------");
        match apply_li_transform(&mut inst.clone()) {
            Ok(res) => {
                for i in res {
                    formatted_inst.clear();
                    formatter.format(&mut i.clone(), &mut formatted_inst);
                    println!("[+] {}", formatted_inst);
                }
            }
            Err(e) => {
                println!("[-] {e}");
            }
        }
        println!("---------------------");
    }

    #[test]
    fn test_get_random_gp_register() {
        match get_random_gp_register(false, 4, None) {
            Ok(reg) => assert_eq!(reg.size(), 4),
            Err(e) => println!("[-] {e}"),
        };
    }
}

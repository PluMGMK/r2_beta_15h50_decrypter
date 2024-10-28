use std::env::args;

fn main() {
    // Assume the filename of interest is the LAST argument on the command line.
    let exe_name: String = args().next_back().unwrap();
    let mut exe_data = std::fs::read(&exe_name).expect("Could not read file");

    // Get the udata into a mutable slice
    // TODO: Would be nice to get this by parsing the PE header...
    let udata_offset: usize = 0x20B800;
    let udata_size: usize = 0x12A00;
    let udata = &mut exe_data[udata_offset..(udata_offset+udata_size)];

    // Now we look for calls to the decryption function in sequence. Each time we find one, we
    // execute the corresponding decryption ourselves and disarm the call. Then this should have
    // decrypted the next one, so we look for that. It's an iterative process, which stops when
    // there are no more decryption calls to find.
    let mut search_start = 0;
    // The decryption function is replicated at these offsets:
    let decrypt_fn_offsets = vec![0x4,0x460];
    println!("Decrypting '.udata' section");
    while let Some((ret_point,length,init_sub_key,init_xor_key,sub_key_addend,xor_key_addend)) = find_decrypt_call(udata, &decrypt_fn_offsets, search_start) {
        // Decrypt it
        let passage = &mut udata[ret_point..(ret_point+length)];
        decrypt_passage(passage,init_sub_key,init_xor_key,sub_key_addend,xor_key_addend);
        println!("Decrypted passage at 0x{:08X} of size 0x{:08X}", ret_point, length);
        // Disarm the decryption call
        disarm_decrypt_call(udata,ret_point);
        // Update the starting point for the next search
        search_start = ret_point;
    }

    // Grab the true entry point from the decrypted ".udata"
    let entry_rva_bytes = Vec::from(&udata[0x1df2..0x1df6]); // Copy the slice rather than borrowing it
    let entry_rva = u32::from_le_bytes(entry_rva_bytes[..].try_into().unwrap());

    // Now that ".udata" is done, we need to do the other sections as well...
    // .idata
    let idata_offset: usize = 0x1E6800;
    let idata_rva_bytes = Vec::from(&udata[0x1e72..0x1e76]); // Copy the slice rather than borrowing it
    let idata_rva = u32::from_le_bytes(idata_rva_bytes[..].try_into().unwrap());
    let idata_decryption_length: usize = u32::from_le_bytes(udata[0x1e76..0x1e7a]
                                                            .try_into().unwrap()) // Slice --> array
        .try_into().unwrap(); // u32 --> usize
    let idata_init_sub_key = udata[0x1e7a];
    let idata_init_sub_key_addend = udata[0x1e7b];
    let idata_sub_key_addend_addend = udata[0x1e7c];
    // .data
    let data_offset: usize = 0x400;
    let data_decryption_length: usize = u32::from_le_bytes(udata[0x1e96..0x1e9a]
                                                           .try_into().unwrap()) // Slice --> array
        .try_into().unwrap(); // u32 --> usize
    let data_init_sub_key = udata[0x1e9a];
    let data_init_sub_key_addend = udata[0x1e9b];
    let data_sub_key_addend_addend = udata[0x1e9c];
    // .text
    let text_offset: usize = 0x1AAE00;
    let text_decryption_length: usize = u32::from_le_bytes(udata[0x1eb6..0x1eba]
                                                           .try_into().unwrap()) // Slice --> array
        .try_into().unwrap(); // u32 --> usize
    let text_init_sub_key = udata[0x1eba];
    let text_init_sub_key_addend = udata[0x1ebb];
    let text_sub_key_addend_addend = udata[0x1ebc];

    // Actually perform the decryptions
    let data = &mut exe_data[data_offset..(data_offset+data_decryption_length)];
    println!("Decrypting '.data' section");
    decrypt_section(data,data_init_sub_key,data_init_sub_key_addend,data_sub_key_addend_addend);
    let text = &mut exe_data[text_offset..(text_offset+text_decryption_length)];
    println!("Decrypting '.text' section");
    decrypt_section(text,text_init_sub_key,text_init_sub_key_addend,text_sub_key_addend_addend);
    let idata = &mut exe_data[idata_offset..(idata_offset+idata_decryption_length)];
    println!("Decrypting '.idata' section");
    decrypt_section(idata,idata_init_sub_key,idata_init_sub_key_addend,idata_sub_key_addend_addend);

    // Now that ".idata" is decrypted, we can point the import table pointers at it
    // instead of at the stub one hidden in ".udata" that IDA complains about
    // Determine the length of the IDT
    let idt_entry_size = 0x14; // Standard constant
    let mut iat_rvas = vec![];
    for entry in idata.chunks(idt_entry_size){
        let iat_rva = u32::from_le_bytes(entry[0x10..0x14].try_into().unwrap());
        iat_rvas.push(iat_rva);
        if iat_rva == 0 {
            break;
        }
    };
    let num_entries = iat_rvas.len();
    let idt_len: u32 = (idt_entry_size * num_entries).try_into().unwrap();

    // Determine position and total length of the IATs
    // Leave out the last one from the "min" calculation, as it is always zero!
    let earliest_iat_rva = iat_rvas[..num_entries-1].iter().min().unwrap();
    let latest_iat_rva = iat_rvas.iter().max().unwrap();
    let latest_iat_off = (latest_iat_rva - idata_rva).try_into().unwrap();
    // Run through the last IAT and find when the zero entries start.
    let mut end_iat_rva = *latest_iat_rva;
    for iat_entry in idata[latest_iat_off..].chunks(4) {
        let iat_entry_rva = u32::from_le_bytes(iat_entry.try_into().unwrap());
        if iat_entry_rva == 0 {
            break;
        }
        end_iat_rva += 4;
    }
    let iat_len = end_iat_rva - earliest_iat_rva;

    // Actually set the table entries
    let idt_ptr_offset = 0x100; // The IMAGE_DATA_DIRECTORY pointing at the Import Directory Table is here in the file.
    exe_data[idt_ptr_offset..(idt_ptr_offset+4)].copy_from_slice(&idata_rva_bytes);
    exe_data[(idt_ptr_offset+4)..(idt_ptr_offset+8)].copy_from_slice(&idt_len.to_le_bytes());
    println!("Set Import Directory Table RVA to 0x{:08X} and length to 0x{:08X}",
             idata_rva,
             idt_len);

    let iat_ptr_offset = 0x158; // The IMAGE_DATA_DIRECTORY pointing at the Import Address Table is here in the file.
    exe_data[iat_ptr_offset..(iat_ptr_offset+4)].copy_from_slice(&earliest_iat_rva.to_le_bytes());
    exe_data[(iat_ptr_offset+4)..(iat_ptr_offset+8)].copy_from_slice(&iat_len.to_le_bytes());
    println!("Set Import Address Table RVA to 0x{:08X} and length to 0x{:08X}",
             earliest_iat_rva,
             iat_len);

    // Fix the entry point
    let entry_ptr_offset = 0xA8; // The pointer to the entry point is here in the file.
    exe_data[entry_ptr_offset..(entry_ptr_offset+4)].copy_from_slice(&entry_rva_bytes);
    println!("Set Entry Point RVA to 0x{:08X}",
             entry_rva);

    // Save the data to a new file
    let new_exe = format!("{}.decrypted.exe",exe_name);
    std::fs::write(&new_exe, &exe_data).expect("Could not write file");
}

/// Find a call to the MaiCFXvr.exe ".udata" decryption function and return its parameters for use
/// with the `decrypt_passage` function below.
///
/// Details:
/// This function looks through the bytes in `section`, starting from the offset `search_start`, to
/// find the following 15-byte sequence of IA-32 instructions:
/// ```
///     push    <length>
///     push    <key>
///     call    <decrypt_fn_offset>
/// ```
/// Once it finds this sequence, this function returns a tuple with the following elements:
/// * The return point of the decryption call (i.e. starting offset of the chunk to decrypt)
/// * The length of the chunk to decrypt
/// * The initial subtraction key
/// * The initial xor key
/// * The subtraction key addend
/// * The xor key addend
fn find_decrypt_call(section: &[u8], decrypt_fn_offsets: &[usize], search_start: usize) -> Option<(usize,usize,u8,u8,u8,u8)> {
    for (idx,win) in section[search_start..].windows(15).enumerate() {
        let off = idx+search_start;
        // Check for first `push` instruction
        if win[0] != 0x68 {
            continue;
        }
        // Check for second `push` instruction
        if win[5] != 0x68 {
            continue;
        }
        // Check for `call` instruction
        if win[10] != 0xE8 {
            continue;
        }
        // Ensure the `call` goes to where we want.
        let ret_point = off+15; // The `call` returns at the end of this 15-byte window
        let call_offset: isize = i32::from_le_bytes(win[11..15]
                                                    .try_into().unwrap()) // Slice --> array
            .try_into().unwrap(); // i32 --> isize
        let call_dest = ret_point.wrapping_add_signed(call_offset);
        if !decrypt_fn_offsets.contains(&call_dest) {
            continue;
        }
        // Right, we have a legitimate call to the decryption function, so parse it.
        let length = u32::from_le_bytes(win[1..5]
                                        .try_into().unwrap()) // Slice --> array
            .try_into().unwrap(); // u32 --> usize
        // The `key` DWORD parameter is basically four distinct bytes:
        let init_sub_key = win[6];
        let init_xor_key = win[7];
        let sub_key_addend = win[8];
        let xor_key_addend = win[9];
        // Return the data
        return Some((ret_point,length,init_sub_key,init_xor_key,sub_key_addend,xor_key_addend));
    };
    // Didn't find any calls
    None
}

/// Disarm a call to the decrypt function in the ".udata" section of MaiCFXvr.exe by nullifying its
/// initial keys.
///
/// Details:
/// This function takes a mutable slice of bytes representing the contents of the ".udata" section,
/// and the offset of the return point of the decrypt function. All calls to the decrypt function
/// have the same 15-byte formula, so it can track back from the `ret_point` to find the two bytes
/// to nullify.
fn disarm_decrypt_call(section: &mut [u8], ret_point: usize) {
    let key_offset = ret_point - (15-6);
    section[key_offset] = 0; // Nullify initial subtraction key
    section[key_offset+1] = 0; // Nullify initial xor key
}

/// Decrypt a chunk of the ".udata" section of MaiCFXvr.exe using the same algorithm as it uses
/// internally. The parameter `passage` points at the raw bytes of the chunk, which are updated
/// in-place.
fn decrypt_passage(passage: &mut [u8], init_sub_key: u8, init_xor_key: u8, sub_key_addend: u8, xor_key_addend: u8) {
    let mut sub_key = init_sub_key;
    let mut xor_key = init_xor_key;
    for byte in passage {
        *byte = byte.wrapping_sub(sub_key);
        *byte ^= xor_key;
        // Update the keys themselves for next byte
        sub_key = sub_key.wrapping_add(sub_key_addend);
        xor_key = xor_key.wrapping_add(xor_key_addend);
    }
}

/// Decrypt the ".idata"/".data"/".text" section of MaiCFXvr.exe using the same algorithm it uses internally.
fn decrypt_section(section: &mut [u8], init_sub_key: u8, init_sub_key_addend: u8, sub_key_addend_addend: u8) {
    let mut sub_key = init_sub_key;
    let mut sub_key_addend = init_sub_key_addend;
    for byte in section {
        *byte = byte.wrapping_sub(sub_key);
        // Update the keys themselves for next byte
        sub_key = sub_key.wrapping_add(sub_key_addend);
        sub_key_addend = sub_key_addend.wrapping_add(sub_key_addend_addend);
    }
}

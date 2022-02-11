// This script attempts to find all instances of encrypted strings, decrypt them and write them back to the database
// It expects an initialized S array to be dumped into c:\\key.bin prior to execution
// The cursor should be placed to the decryption routine (for sample 0a0c225f0e5ee941a79f2b7701f1285e4975a2859eb4d025d96d9e366e81abb9, it will be 0x401DE4)
#include <idc.idc>

static read_key(key_path) {
  auto f, key;
  f = open_loader_input(key_path, 0);
  f.read(&key, f.size());
  f.close();
  return key;
}

static read_string(address) {
  auto size, str;
  size = long(dword(address-4));
  if (size > 0xFFFF) {
    msg("Warning, too long string at %X, skipping\n", address);
    return "";
  }
  str = get_bytes(address, size, 0);
  return str;
}

static write_string(address, dec_string) {
  auto i;
  for (i=0; i < strlen(dec_string); i=i+1) {
    patch_byte(address+i, ord(dec_string[i]));
  }
}

static decrypt_string(enc_string, key) {
  auto key_swap_index, value1, value2, key_index, key_byte, i;  
  key_swap_index = 0;
  for(i=0; i<strlen(enc_string); i=i+1) {
    key_swap_index = (key_swap_index + ord(key[i+1])) & 0xFF;
    value1 = key[i+1];
    value2 = key[key_swap_index];
    key[i+1] = value2;
    key[key_swap_index] = value1;
    key_index = (ord(value1) + ord(value2)) & 0xFF;
    key_byte = key[key_index];
    enc_string[i] = ord(enc_string[i]) ^ ord(key_byte);
  }
  return enc_string;
}

static hexlify(string) {
  auto i;
  auto result = "";
  for(i=0; i<strlen(string); i=i+1) {
    result[i*2] = sprintf("%02x", ord(string[i]) & 0xFF);
  }
  return result;
}

static make_string(address) {
  auto result;
  set_inf_attr(INF_STRTYPE, STRWIDTH_2B);
  result = create_strlit(address);
  set_inf_attr(INF_STRTYPE, STRWIDTH_1B);
  if (result == 0) {
    create_strlit(address);
  }
}

static main()
{
  auto key, decryption_routine, ea, temp_ea, i, inst, op1, enc_string, dec_string, address, min_addr, max_addr;
  msg("Starting the decryption process\n");
  key = read_key("c:\\key.bin");
  decryption_routine = get_screen_ea();
  msg("Decryption routine at %X\n", decryption_routine);
  ea = get_first_cref_to(decryption_routine);
  min_addr = get_inf_attr(INF_MIN_EA);
  max_addr = get_inf_attr(INF_MAX_EA);
  while (ea != BADADDR) {
    temp_ea = ea;
    for (i=0; i<5; i=i+1) {
      temp_ea = prev_head(temp_ea, 0);
      if (is_code(get_flags(temp_ea)) == 0) {
        continue;
      }
      inst = print_insn_mnem(temp_ea);
      address = get_operand_value(temp_ea, 0);
      if (address < min_addr || address > max_addr) {
        continue;
      }
      if (inst == "push") {
        msg("Candidate string at %X: %X\n", temp_ea, address);
        enc_string = read_string(address);
        msg("Encrypted: " + hexlify(enc_string) + "\n");
        dec_string = decrypt_string(enc_string, key);
        msg("Decrypted: " + hexlify(dec_string) + "\n");
        write_string(address, dec_string);
        make_string(address);
        break;
      }
    }
    ea = get_next_cref_to(decryption_routine, ea);
  }
}


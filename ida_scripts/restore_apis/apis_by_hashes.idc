// This script searches for all cross-references to the api-resolving function pointed by the cursor and maps the identified api hashes (passed via r8d in this case) to the corresponding api names using a pre-built list matches.txt
// Example of a single matches.txt entry: 2CA5F366 - lstrcpyA
#include <idc.idc>

static read_matches(file_path) {
  auto f = fopen(file_path, "r");
  if (f == 0) {
    warning("No file to read the matches from!\n");
    return;
  }
  auto line = readstr(f);
  auto matches = create_array("matches");
  if (matches == -1) {
    matches = get_array_id("matches");
  }
  while (line != -1) {
    set_hash_string(matches, substr(line, 0, 8), substr(line, 11, -2));
    line = readstr(f);
  }
  fclose(f);
  return matches;
}

static main()
{
  auto ea, temp_ea, resolver, i, inst, op1, op2, hash, matches, match, api_name;
  msg("================\n");  
  resolver = get_screen_ea();
  matches = read_matches("c:\\matches.txt");
  ea = get_first_cref_to(resolver);
  while (ea != BADADDR) {
    temp_ea = ea;
    for (i=0; i<6; i=i+1) {
      temp_ea = prev_head(temp_ea, 0);
      if (is_code(get_flags(temp_ea)) == 0) {
        continue;
      }
      inst = print_insn_mnem(temp_ea);
      op1 = get_operand_value(temp_ea, 0);
      op2 = get_operand_value(temp_ea, 1) & 0xFFFFFFFF;
      // adjust the details of the instruction that contains an API hash according to your sample
      if (inst == "mov" && op1 == 8) {
        hash = sprintf("%08X", op2);
        match = get_first_hash_key(matches);
        while (match != 0) {
          if (hash == match) {
             api_name = get_hash_string(matches, match);
             msg("%X: %s-%s\n", temp_ea, hash, api_name);
             set_cmt(ea, api_name, 1);
             break;
          } 
          match = get_next_hash_key(matches, match);;
        }
        break;
      }
    }
    ea = get_next_cref_to(resolver, ea);
  }
}


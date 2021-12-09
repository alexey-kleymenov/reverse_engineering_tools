// A quick-and-dirty script that searches for all cross-references to the api-resolving function pointed by the cursor and maps the identified api hashes (passed via r8d in this case) to the corresponding api names using a pre-built list matches.txt
// Example of a single matches.txt entry: 2CA5F366 - lstrcpyA
static main()
{
  auto ea, temp_ea, resolver, i, inst, op1, op2, hash, mappings, next_line, api_name;
  msg("================\n");  
  resolver = get_screen_ea();
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
      if (inst == "mov" && op1 == 8) {
        hash = sprintf("%08X", op2);
        // absolutely ugly performance-wise but IDC doesn't support lists or dictionaries
        mappings = fopen("c:\\matches.txt", "r");
        next_line = readstr(mappings);
        while (next_line != -1) {
          if (strstr(next_line, hash) == 0) {
             api_name = substr(next_line, 11, -1);
             msg("%X: %s-%s", temp_ea, hash, api_name);
             set_cmt(ea, api_name, 1);
             break;
          } 
          next_line = readstr(mappings);
        }
        fclose(mappings);
        break;
      }
    }
    ea = get_next_cref_to(resolver, ea);
  }
}

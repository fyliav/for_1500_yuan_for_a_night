import logging

import angr
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from cart.cart import text_type
from markdown_it.rules_core import text_join

logging.getLogger('angr').setLevel(logging.ERROR)
logging.getLogger('claripy').setLevel(logging.ERROR)
logging.getLogger('pyvex').setLevel(logging.ERROR)
logging.getLogger('cle').setLevel(logging.ERROR)

disasm = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

project = angr.Project(r'D:\desktop\ollvm\vbox\l03c1596c_a64.so', auto_load_libs=False,
                       load_options={'main_opts': {'base_addr': 0}})
state = project.factory.entry_state()
base = project.loader.min_addr

text_section = None
for section in project.loader.main_object.sections:
    if section.name == '.text':
        text_section = section
        break

text_start = text_section.vaddr
text_end = text_section.vaddr + text_section.memsize
print("base", hex(base))
print("text_start", hex(text_start))
print("text_end", hex(text_end))
current_addr = text_start
brlist = []
# while current_addr < text_end:
#     code = state.memory.load(current_addr, 4)
#     code_bytes = state.solver.eval(code, cast_to=bytes)
#     for instr in disasm.disasm(code_bytes, current_addr):
#         if instr and hasattr(instr, "mnemonic") and instr.mnemonic == "br":
#             print(instr)
#             brlist.append({
#                 "addr": current_addr,
#                 "reg": instr.op_str,
#             })
#     current_addr += 4
brlist = [{'addr': 162596, 'reg': 'x17'}, {'addr': 163420, 'reg': 'x7'}, {'addr': 164220, 'reg': 'x8'},
          {'addr': 164372, 'reg': 'x30'}, {'addr': 165192, 'reg': 'x16'}, {'addr': 166168, 'reg': 'x10'},
          {'addr': 166588, 'reg': 'x6'}, {'addr': 166924, 'reg': 'x9'}, {'addr': 167268, 'reg': 'x7'},
          {'addr': 167364, 'reg': 'x30'}, {'addr': 167716, 'reg': 'x14'}, {'addr': 167860, 'reg': 'x30'},
          {'addr': 168148, 'reg': 'x3'}, {'addr': 168484, 'reg': 'x30'}, {'addr': 168516, 'reg': 'x6'},
          {'addr': 168784, 'reg': 'x14'}, {'addr': 169052, 'reg': 'x11'}, {'addr': 170420, 'reg': 'x15'},
          {'addr': 170688, 'reg': 'x12'}, {'addr': 171520, 'reg': 'x8'}, {'addr': 171928, 'reg': 'x10'},
          {'addr': 172924, 'reg': 'x8'}, {'addr': 173204, 'reg': 'x13'}, {'addr': 173460, 'reg': 'x14'},
          {'addr': 174936, 'reg': 'x8'}, {'addr': 175832, 'reg': 'x8'}, {'addr': 177236, 'reg': 'x8'},
          {'addr': 178216, 'reg': 'x8'}, {'addr': 180128, 'reg': 'x8'}, {'addr': 181120, 'reg': 'x8'},
          {'addr': 181712, 'reg': 'x8'}, {'addr': 181972, 'reg': 'x17'}, {'addr': 182752, 'reg': 'x8'},
          {'addr': 183048, 'reg': 'x5'}, {'addr': 183320, 'reg': 'x5'}, {'addr': 184516, 'reg': 'x3'},
          {'addr': 184964, 'reg': 'x9'}, {'addr': 186436, 'reg': 'x8'}, {'addr': 186764, 'reg': 'x1'},
          {'addr': 187036, 'reg': 'x7'}, {'addr': 188252, 'reg': 'x7'}, {'addr': 191428, 'reg': 'x19'},
          {'addr': 191708, 'reg': 'x14'}, {'addr': 191996, 'reg': 'x4'}, {'addr': 192416, 'reg': 'x7'},
          {'addr': 192688, 'reg': 'x3'}, {'addr': 194168, 'reg': 'x8'}, {'addr': 195368, 'reg': 'x14'},
          {'addr': 195688, 'reg': 'x13'}, {'addr': 196276, 'reg': 'x30'}, {'addr': 197172, 'reg': 'x10'},
          {'addr': 198256, 'reg': 'x6'}, {'addr': 199196, 'reg': 'x6'}, {'addr': 199476, 'reg': 'x4'},
          {'addr': 199796, 'reg': 'x13'}, {'addr': 200404, 'reg': 'x8'}, {'addr': 200912, 'reg': 'x11'},
          {'addr': 201016, 'reg': 'x6'}, {'addr': 201828, 'reg': 'x30'}, {'addr': 202104, 'reg': 'x7'},
          {'addr': 202372, 'reg': 'x17'}, {'addr': 202728, 'reg': 'x2'}, {'addr': 203728, 'reg': 'x15'},
          {'addr': 205120, 'reg': 'x8'}, {'addr': 205376, 'reg': 'x13'}, {'addr': 207424, 'reg': 'x15'},
          {'addr': 207720, 'reg': 'x19'}, {'addr': 208052, 'reg': 'x5'}, {'addr': 208372, 'reg': 'x6'},
          {'addr': 209308, 'reg': 'x8'}, {'addr': 210096, 'reg': 'x12'}, {'addr': 210464, 'reg': 'x12'},
          {'addr': 210564, 'reg': 'x30'}, {'addr': 211396, 'reg': 'x8'}, {'addr': 211688, 'reg': 'x5'},
          {'addr': 212472, 'reg': 'x8'}, {'addr': 213324, 'reg': 'x8'}, {'addr': 214060, 'reg': 'x4'},
          {'addr': 215168, 'reg': 'x11'}, {'addr': 216320, 'reg': 'x0'}, {'addr': 216608, 'reg': 'x5'},
          {'addr': 217528, 'reg': 'x15'}, {'addr': 218152, 'reg': 'x6'}, {'addr': 218980, 'reg': 'x8'},
          {'addr': 219048, 'reg': 'x6'}, {'addr': 219296, 'reg': 'x7'}, {'addr': 220212, 'reg': 'x11'},
          {'addr': 220480, 'reg': 'x6'}, {'addr': 220804, 'reg': 'x4'}, {'addr': 221096, 'reg': 'x1'},
          {'addr': 221344, 'reg': 'x0'}, {'addr': 221624, 'reg': 'x19'}, {'addr': 222884, 'reg': 'x14'},
          {'addr': 224120, 'reg': 'x8'}, {'addr': 224460, 'reg': 'x7'}, {'addr': 224820, 'reg': 'x14'},
          {'addr': 225220, 'reg': 'x1'}, {'addr': 226400, 'reg': 'x10'}, {'addr': 226696, 'reg': 'x7'},
          {'addr': 226928, 'reg': 'x3'}, {'addr': 227188, 'reg': 'x0'}, {'addr': 227700, 'reg': 'x6'},
          {'addr': 229604, 'reg': 'x15'}, {'addr': 230288, 'reg': 'x13'}, {'addr': 231692, 'reg': 'x8'},
          {'addr': 231992, 'reg': 'x5'}, {'addr': 232360, 'reg': 'x8'}, {'addr': 233096, 'reg': 'x8'},
          {'addr': 233480, 'reg': 'x17'}, {'addr': 234500, 'reg': 'x8'}, {'addr': 234812, 'reg': 'x8'},
          {'addr': 235116, 'reg': 'x5'}, {'addr': 235400, 'reg': 'x13'}, {'addr': 237244, 'reg': 'x14'},
          {'addr': 237576, 'reg': 'x0'}, {'addr': 239920, 'reg': 'x8'}, {'addr': 239976, 'reg': 'x6'},
          {'addr': 240904, 'reg': 'x16'}, {'addr': 241232, 'reg': 'x6'}, {'addr': 242032, 'reg': 'x8'},
          {'addr': 242284, 'reg': 'x2'}, {'addr': 242604, 'reg': 'x19'}, {'addr': 242708, 'reg': 'x30'},
          {'addr': 243096, 'reg': 'x8'}, {'addr': 243272, 'reg': 'x6'}, {'addr': 243580, 'reg': 'x2'},
          {'addr': 244784, 'reg': 'x10'}, {'addr': 245580, 'reg': 'x8'}, {'addr': 246132, 'reg': 'x5'},
          {'addr': 247572, 'reg': 'x8'}, {'addr': 248096, 'reg': 'x11'}, {'addr': 250728, 'reg': 'x8'},
          {'addr': 251024, 'reg': 'x9'}, {'addr': 251720, 'reg': 'x8'}, {'addr': 252056, 'reg': 'x5'},
          {'addr': 253060, 'reg': 'x30'}, {'addr': 253400, 'reg': 'x9'}, {'addr': 253684, 'reg': 'x10'},
          {'addr': 253964, 'reg': 'x15'}, {'addr': 254568, 'reg': 'x10'}, {'addr': 254952, 'reg': 'x10'},
          {'addr': 255200, 'reg': 'x11'}, {'addr': 255492, 'reg': 'x15'}, {'addr': 255588, 'reg': 'x30'},
          {'addr': 255860, 'reg': 'x13'}, {'addr': 256200, 'reg': 'x5'}, {'addr': 257256, 'reg': 'x8'},
          {'addr': 257588, 'reg': 'x6'}, {'addr': 257896, 'reg': 'x3'}, {'addr': 258940, 'reg': 'x4'},
          {'addr': 259044, 'reg': 'x30'}, {'addr': 259284, 'reg': 'x1'}, {'addr': 259540, 'reg': 'x5'},
          {'addr': 259684, 'reg': 'x30'}, {'addr': 260008, 'reg': 'x6'}, {'addr': 260332, 'reg': 'x3'},
          {'addr': 261092, 'reg': 'x30'}, {'addr': 261188, 'reg': 'x30'}, {'addr': 261472, 'reg': 'x7'},
          {'addr': 261700, 'reg': 'x2'}, {'addr': 262168, 'reg': 'x7'}, {'addr': 262508, 'reg': 'x8'},
          {'addr': 262828, 'reg': 'x9'}, {'addr': 263260, 'reg': 'x9'}, {'addr': 263676, 'reg': 'x11'},
          {'addr': 263968, 'reg': 'x1'}, {'addr': 264324, 'reg': 'x5'}, {'addr': 264504, 'reg': 'x6'},
          {'addr': 265040, 'reg': 'x0'}, {'addr': 265756, 'reg': 'x5'}, {'addr': 265860, 'reg': 'x30'},
          {'addr': 268428, 'reg': 'x3'}, {'addr': 268992, 'reg': 'x2'}, {'addr': 269312, 'reg': 'x7'},
          {'addr': 269588, 'reg': 'x15'}, {'addr': 269860, 'reg': 'x11'}, {'addr': 270264, 'reg': 'x3'},
          {'addr': 272052, 'reg': 'x6'}, {'addr': 272416, 'reg': 'x2'}, {'addr': 273432, 'reg': 'x8'},
          {'addr': 273712, 'reg': 'x19'}, {'addr': 274788, 'reg': 'x9'}, {'addr': 274884, 'reg': 'x30'},
          {'addr': 275168, 'reg': 'x16'}, {'addr': 275464, 'reg': 'x7'}, {'addr': 276156, 'reg': 'x8'},
          {'addr': 276492, 'reg': 'x2'}, {'addr': 276888, 'reg': 'x5'}, {'addr': 277436, 'reg': 'x5'},
          {'addr': 277876, 'reg': 'x8'}, {'addr': 278136, 'reg': 'x3'}, {'addr': 278428, 'reg': 'x9'},
          {'addr': 279292, 'reg': 'x13'}, {'addr': 280628, 'reg': 'x30'}, {'addr': 280884, 'reg': 'x15'},
          {'addr': 281140, 'reg': 'x3'}, {'addr': 281480, 'reg': 'x14'}, {'addr': 281748, 'reg': 'x19'},
          {'addr': 282568, 'reg': 'x8'}, {'addr': 282824, 'reg': 'x2'}, {'addr': 283668, 'reg': 'x8'},
          {'addr': 283780, 'reg': 'x30'}, {'addr': 284108, 'reg': 'x6'}, {'addr': 284444, 'reg': 'x10'},
          {'addr': 284748, 'reg': 'x19'}, {'addr': 285032, 'reg': 'x17'}, {'addr': 285428, 'reg': 'x13'},
          {'addr': 287532, 'reg': 'x12'}, {'addr': 288556, 'reg': 'x8'}, {'addr': 288832, 'reg': 'x0'},
          {'addr': 289104, 'reg': 'x2'}, {'addr': 289376, 'reg': 'x7'}, {'addr': 289860, 'reg': 'x13'},
          {'addr': 290732, 'reg': 'x6'}, {'addr': 291796, 'reg': 'x8'}, {'addr': 292128, 'reg': 'x17'},
          {'addr': 292420, 'reg': 'x1'}, {'addr': 293452, 'reg': 'x0'}, {'addr': 293700, 'reg': 'x17'},
          {'addr': 293972, 'reg': 'x6'}, {'addr': 295720, 'reg': 'x8'}, {'addr': 296024, 'reg': 'x3'},
          {'addr': 296168, 'reg': 'x6'}, {'addr': 297312, 'reg': 'x19'}, {'addr': 297412, 'reg': 'x30'},
          {'addr': 297688, 'reg': 'x6'}, {'addr': 298644, 'reg': 'x7'}, {'addr': 298944, 'reg': 'x13'},
          {'addr': 299284, 'reg': 'x2'}, {'addr': 299532, 'reg': 'x1'}, {'addr': 299788, 'reg': 'x17'},
          {'addr': 300068, 'reg': 'x10'}, {'addr': 300392, 'reg': 'x4'}, {'addr': 300688, 'reg': 'x19'},
          {'addr': 300968, 'reg': 'x16'}, {'addr': 301476, 'reg': 'x6'}, {'addr': 302352, 'reg': 'x8'},
          {'addr': 302820, 'reg': 'x16'}, {'addr': 304296, 'reg': 'x0'}, {'addr': 304344, 'reg': 'x6'},
          {'addr': 305148, 'reg': 'x17'}, {'addr': 305164, 'reg': 'x17'}, {'addr': 305180, 'reg': 'x17'},
          {'addr': 305196, 'reg': 'x17'}, {'addr': 305212, 'reg': 'x17'}, {'addr': 305228, 'reg': 'x17'},
          {'addr': 305244, 'reg': 'x17'}, {'addr': 305260, 'reg': 'x17'}, {'addr': 305276, 'reg': 'x17'},
          {'addr': 305292, 'reg': 'x17'}, {'addr': 305308, 'reg': 'x17'}, {'addr': 305324, 'reg': 'x17'},
          {'addr': 305340, 'reg': 'x17'}, {'addr': 305356, 'reg': 'x17'}, {'addr': 305372, 'reg': 'x17'},
          {'addr': 305388, 'reg': 'x17'}, {'addr': 305404, 'reg': 'x17'}, {'addr': 305420, 'reg': 'x17'},
          {'addr': 305436, 'reg': 'x17'}, {'addr': 305452, 'reg': 'x17'}, {'addr': 305468, 'reg': 'x17'},
          {'addr': 305484, 'reg': 'x17'}, {'addr': 305500, 'reg': 'x17'}, {'addr': 305516, 'reg': 'x17'},
          {'addr': 305532, 'reg': 'x17'}, {'addr': 305548, 'reg': 'x17'}, {'addr': 305564, 'reg': 'x17'},
          {'addr': 305580, 'reg': 'x17'}, {'addr': 306560, 'reg': 'x15'}, {'addr': 306836, 'reg': 'x2'},
          {'addr': 307100, 'reg': 'x8'}, {'addr': 307372, 'reg': 'x12'}, {'addr': 307684, 'reg': 'x0'},
          {'addr': 307780, 'reg': 'x30'}, {'addr': 307812, 'reg': 'x6'}, {'addr': 308108, 'reg': 'x11'},
          {'addr': 308244, 'reg': 'x6'}, {'addr': 308588, 'reg': 'x16'}, {'addr': 308872, 'reg': 'x14'},
          {'addr': 309132, 'reg': 'x3'}, {'addr': 310124, 'reg': 'x13'}, {'addr': 310228, 'reg': 'x30'},
          {'addr': 311024, 'reg': 'x8'}, {'addr': 311284, 'reg': 'x16'}, {'addr': 311760, 'reg': 'x1'},
          {'addr': 311892, 'reg': 'x30'}, {'addr': 312264, 'reg': 'x9'}, {'addr': 312512, 'reg': 'x13'},
          {'addr': 312612, 'reg': 'x30'}, {'addr': 312916, 'reg': 'x5'}, {'addr': 313500, 'reg': 'x10'},
          {'addr': 313672, 'reg': 'x6'}, {'addr': 313940, 'reg': 'x15'}, {'addr': 314236, 'reg': 'x4'},
          {'addr': 314392, 'reg': 'x6'}, {'addr': 314744, 'reg': 'x15'}, {'addr': 315004, 'reg': 'x9'},
          {'addr': 315304, 'reg': 'x9'}, {'addr': 316416, 'reg': 'x6'}, {'addr': 316748, 'reg': 'x7'},
          {'addr': 317068, 'reg': 'x0'}, {'addr': 317372, 'reg': 'x16'}, {'addr': 318780, 'reg': 'x14'},
          {'addr': 318888, 'reg': 'x6'}, {'addr': 319900, 'reg': 'x7'}, {'addr': 320324, 'reg': 'x19'},
          {'addr': 320580, 'reg': 'x2'}, {'addr': 321384, 'reg': 'x8'}, {'addr': 321716, 'reg': 'x10'},
          {'addr': 322072, 'reg': 'x13'}, {'addr': 322416, 'reg': 'x5'}, {'addr': 322536, 'reg': 'x6'},
          {'addr': 322820, 'reg': 'x12'}, {'addr': 323140, 'reg': 'x14'}, {'addr': 323484, 'reg': 'x3'},
          {'addr': 324424, 'reg': 'x8'}, {'addr': 324688, 'reg': 'x13'}, {'addr': 325176, 'reg': 'x3'},
          {'addr': 325476, 'reg': 'x13'}, {'addr': 325772, 'reg': 'x2'}, {'addr': 328644, 'reg': 'x8'},
          {'addr': 329100, 'reg': 'x16'}, {'addr': 329612, 'reg': 'x0'}, {'addr': 330388, 'reg': 'x8'},
          {'addr': 330672, 'reg': 'x19'}, {'addr': 331756, 'reg': 'x2'}, {'addr': 332460, 'reg': 'x6'},
          {'addr': 332776, 'reg': 'x0'}, {'addr': 333732, 'reg': 'x13'}, {'addr': 334644, 'reg': 'x8'},
          {'addr': 335492, 'reg': 'x10'}, {'addr': 335636, 'reg': 'x30'}, {'addr': 335688, 'reg': 'x6'},
          {'addr': 335952, 'reg': 'x1'}, {'addr': 336952, 'reg': 'x3'}, {'addr': 337924, 'reg': 'x8'},
          {'addr': 338252, 'reg': 'x1'}, {'addr': 338548, 'reg': 'x1'}, {'addr': 338844, 'reg': 'x4'},
          {'addr': 339272, 'reg': 'x8'}, {'addr': 339932, 'reg': 'x3'}, {'addr': 340332, 'reg': 'x12'},
          {'addr': 340720, 'reg': 'x9'}, {'addr': 340996, 'reg': 'x1'}, {'addr': 341264, 'reg': 'x15'},
          {'addr': 341612, 'reg': 'x6'}, {'addr': 342244, 'reg': 'x19'}, {'addr': 342676, 'reg': 'x8'},
          {'addr': 342944, 'reg': 'x0'}, {'addr': 343428, 'reg': 'x2'}, {'addr': 343708, 'reg': 'x17'},
          {'addr': 343992, 'reg': 'x13'}, {'addr': 344296, 'reg': 'x3'}, {'addr': 345124, 'reg': 'x15'},
          {'addr': 345452, 'reg': 'x8'}, {'addr': 345728, 'reg': 'x14'}, {'addr': 346012, 'reg': 'x14'},
          {'addr': 346392, 'reg': 'x1'}, {'addr': 346712, 'reg': 'x19'}, {'addr': 347632, 'reg': 'x8'},
          {'addr': 347912, 'reg': 'x3'}, {'addr': 348292, 'reg': 'x17'}, {'addr': 349676, 'reg': 'x8'},
          {'addr': 349968, 'reg': 'x5'}, {'addr': 350556, 'reg': 'x10'}, {'addr': 350852, 'reg': 'x6'},
          {'addr': 351144, 'reg': 'x10'}, {'addr': 352144, 'reg': 'x8'}, {'addr': 352452, 'reg': 'x3'},
          {'addr': 352796, 'reg': 'x5'}, {'addr': 353560, 'reg': 'x8'}, {'addr': 355400, 'reg': 'x6'},
          {'addr': 355656, 'reg': 'x19'}, {'addr': 355748, 'reg': 'x30'}, {'addr': 356712, 'reg': 'x1'},
          {'addr': 356976, 'reg': 'x16'}, {'addr': 357308, 'reg': 'x3'}, {'addr': 357596, 'reg': 'x5'},
          {'addr': 357884, 'reg': 'x7'}, {'addr': 359260, 'reg': 'x1'}, {'addr': 359824, 'reg': 'x14'},
          {'addr': 360080, 'reg': 'x6'}, {'addr': 360716, 'reg': 'x8'}, {'addr': 361544, 'reg': 'x8'},
          {'addr': 363024, 'reg': 'x7'}, {'addr': 363284, 'reg': 'x5'}, {'addr': 363300, 'reg': 'x30'},
          {'addr': 363688, 'reg': 'x10'}, {'addr': 364020, 'reg': 'x11'}, {'addr': 364312, 'reg': 'x10'},
          {'addr': 365260, 'reg': 'x8'}, {'addr': 366468, 'reg': 'x16'}, {'addr': 367972, 'reg': 'x17'},
          {'addr': 368240, 'reg': 'x3'}, {'addr': 368676, 'reg': 'x3'}, {'addr': 369156, 'reg': 'x6'},
          {'addr': 369436, 'reg': 'x7'}, {'addr': 369732, 'reg': 'x14'}, {'addr': 370036, 'reg': 'x13'},
          {'addr': 370264, 'reg': 'x11'}, {'addr': 370540, 'reg': 'x5'}, {'addr': 372476, 'reg': 'x3'},
          {'addr': 372724, 'reg': 'x16'}, {'addr': 373504, 'reg': 'x1'}, {'addr': 373652, 'reg': 'x30'},
          {'addr': 373920, 'reg': 'x3'}, {'addr': 374804, 'reg': 'x8'}, {'addr': 375084, 'reg': 'x2'},
          {'addr': 375524, 'reg': 'x6'}, {'addr': 376568, 'reg': 'x1'}, {'addr': 376904, 'reg': 'x15'},
          {'addr': 377200, 'reg': 'x5'}, {'addr': 378036, 'reg': 'x8'}, {'addr': 378460, 'reg': 'x6'},
          {'addr': 378744, 'reg': 'x4'}, {'addr': 378792, 'reg': 'x6'}, {'addr': 379056, 'reg': 'x15'},
          {'addr': 379396, 'reg': 'x12'}, {'addr': 380740, 'reg': 'x14'}, {'addr': 381152, 'reg': 'x6'},
          {'addr': 381748, 'reg': 'x30'}, {'addr': 382124, 'reg': 'x3'}, {'addr': 382556, 'reg': 'x6'},
          {'addr': 382832, 'reg': 'x9'}, {'addr': 383556, 'reg': 'x30'}, {'addr': 383952, 'reg': 'x4'},
          {'addr': 384252, 'reg': 'x6'}, {'addr': 384496, 'reg': 'x6'}, {'addr': 384552, 'reg': 'x6'},
          {'addr': 386596, 'reg': 'x11'}, {'addr': 386888, 'reg': 'x9'}, {'addr': 386984, 'reg': 'x6'},
          {'addr': 387428, 'reg': 'x13'}, {'addr': 388096, 'reg': 'x1'}, {'addr': 388920, 'reg': 'x10'},
          {'addr': 389136, 'reg': 'x6'}, {'addr': 389424, 'reg': 'x15'}, {'addr': 390864, 'reg': 'x16'},
          {'addr': 391864, 'reg': 'x5'}, {'addr': 393224, 'reg': 'x3'}, {'addr': 393316, 'reg': 'x30'},
          {'addr': 393412, 'reg': 'x30'}, {'addr': 393684, 'reg': 'x13'}, {'addr': 393828, 'reg': 'x30'},
          {'addr': 394832, 'reg': 'x7'}, {'addr': 395128, 'reg': 'x6'}, {'addr': 395892, 'reg': 'x8'},
          {'addr': 396388, 'reg': 'x14'}, {'addr': 396884, 'reg': 'x1'}, {'addr': 397132, 'reg': 'x9'},
          {'addr': 397428, 'reg': 'x8'}, {'addr': 397524, 'reg': 'x30'}, {'addr': 397844, 'reg': 'x11'},
          {'addr': 398100, 'reg': 'x5'}, {'addr': 398348, 'reg': 'x1'}, {'addr': 400012, 'reg': 'x0'},
          {'addr': 400100, 'reg': 'x6'}, {'addr': 400360, 'reg': 'x19'}, {'addr': 400684, 'reg': 'x3'},
          {'addr': 401024, 'reg': 'x4'}, {'addr': 403112, 'reg': 'x8'}, {'addr': 403380, 'reg': 'x6'},
          {'addr': 403684, 'reg': 'x30'}, {'addr': 403736, 'reg': 'x6'}, {'addr': 404016, 'reg': 'x15'},
          {'addr': 404872, 'reg': 'x8'}, {'addr': 405500, 'reg': 'x8'}, {'addr': 406208, 'reg': 'x8'},
          {'addr': 406472, 'reg': 'x19'}, {'addr': 407320, 'reg': 'x14'}, {'addr': 407604, 'reg': 'x9'},
          {'addr': 408744, 'reg': 'x6'}, {'addr': 409916, 'reg': 'x8'}, {'addr': 410020, 'reg': 'x30'},
          {'addr': 410380, 'reg': 'x2'}, {'addr': 410624, 'reg': 'x4'}, {'addr': 410980, 'reg': 'x12'},
          {'addr': 411304, 'reg': 'x3'}, {'addr': 411576, 'reg': 'x2'}, {'addr': 411964, 'reg': 'x19'},
          {'addr': 412400, 'reg': 'x13'}, {'addr': 412468, 'reg': 'x30'}, {'addr': 412564, 'reg': 'x30'},
          {'addr': 412872, 'reg': 'x5'}, {'addr': 413204, 'reg': 'x12'}, {'addr': 413540, 'reg': 'x19'},
          {'addr': 413636, 'reg': 'x30'}, {'addr': 415060, 'reg': 'x30'}, {'addr': 415872, 'reg': 'x8'},
          {'addr': 416172, 'reg': 'x17'}, {'addr': 416480, 'reg': 'x9'}, {'addr': 416764, 'reg': 'x1'},
          {'addr': 416868, 'reg': 'x30'}, {'addr': 417012, 'reg': 'x30'}, {'addr': 417156, 'reg': 'x30'},
          {'addr': 417488, 'reg': 'x19'}, {'addr': 417772, 'reg': 'x16'}, {'addr': 418092, 'reg': 'x10'},
          {'addr': 418436, 'reg': 'x19'}, {'addr': 418800, 'reg': 'x12'}, {'addr': 419132, 'reg': 'x9'},
          {'addr': 419416, 'reg': 'x13'}, {'addr': 419764, 'reg': 'x3'}, {'addr': 420012, 'reg': 'x6'},
          {'addr': 420500, 'reg': 'x4'}, {'addr': 420868, 'reg': 'x3'}, {'addr': 421064, 'reg': 'x6'},
          {'addr': 421440, 'reg': 'x15'}, {'addr': 421744, 'reg': 'x17'}, {'addr': 421892, 'reg': 'x30'},
          {'addr': 422136, 'reg': 'x4'}, {'addr': 422456, 'reg': 'x9'}, {'addr': 422764, 'reg': 'x11'},
          {'addr': 423052, 'reg': 'x16'}, {'addr': 425092, 'reg': 'x1'}, {'addr': 425412, 'reg': 'x11'},
          {'addr': 426244, 'reg': 'x8'}, {'addr': 427044, 'reg': 'x14'}, {'addr': 427356, 'reg': 'x13'},
          {'addr': 427516, 'reg': 'x6'}, {'addr': 427932, 'reg': 'x14'}, {'addr': 428764, 'reg': 'x16'},
          {'addr': 429152, 'reg': 'x17'}, {'addr': 429436, 'reg': 'x17'}, {'addr': 429680, 'reg': 'x17'},
          {'addr': 430000, 'reg': 'x12'}, {'addr': 430276, 'reg': 'x5'}, {'addr': 430528, 'reg': 'x15'},
          {'addr': 432052, 'reg': 'x8'}, {'addr': 432388, 'reg': 'x11'}, {'addr': 432828, 'reg': 'x6'},
          {'addr': 434596, 'reg': 'x6'}, {'addr': 435028, 'reg': 'x6'}, {'addr': 435984, 'reg': 'x3'},
          {'addr': 436248, 'reg': 'x15'}, {'addr': 437784, 'reg': 'x8'}, {'addr': 438676, 'reg': 'x8'},
          {'addr': 438976, 'reg': 'x8'}, {'addr': 439260, 'reg': 'x8'}, {'addr': 439416, 'reg': 'x6'},
          {'addr': 440956, 'reg': 'x8'}, {'addr': 441780, 'reg': 'x8'}, {'addr': 442228, 'reg': 'x19'},
          {'addr': 442520, 'reg': 'x2'}, {'addr': 442784, 'reg': 'x9'}, {'addr': 443604, 'reg': 'x8'},
          {'addr': 443860, 'reg': 'x13'}, {'addr': 445052, 'reg': 'x3'}, {'addr': 445812, 'reg': 'x30'},
          {'addr': 446092, 'reg': 'x15'}, {'addr': 446808, 'reg': 'x8'}, {'addr': 447412, 'reg': 'x1'},
          {'addr': 447684, 'reg': 'x14'}, {'addr': 448664, 'reg': 'x9'}, {'addr': 449196, 'reg': 'x2'},
          {'addr': 451964, 'reg': 'x17'}, {'addr': 451980, 'reg': 'x17'}, {'addr': 451996, 'reg': 'x17'},
          {'addr': 452012, 'reg': 'x17'}, {'addr': 452028, 'reg': 'x17'}, {'addr': 452044, 'reg': 'x17'},
          {'addr': 452060, 'reg': 'x17'}, {'addr': 452076, 'reg': 'x17'}, {'addr': 452092, 'reg': 'x17'},
          {'addr': 452108, 'reg': 'x17'}, {'addr': 452124, 'reg': 'x17'}, {'addr': 452140, 'reg': 'x17'},
          {'addr': 452156, 'reg': 'x17'}, {'addr': 452172, 'reg': 'x17'}, {'addr': 452188, 'reg': 'x17'},
          {'addr': 452204, 'reg': 'x17'}, {'addr': 452220, 'reg': 'x17'}, {'addr': 452236, 'reg': 'x17'},
          {'addr': 452252, 'reg': 'x17'}, {'addr': 452268, 'reg': 'x17'}, {'addr': 452284, 'reg': 'x17'},
          {'addr': 452300, 'reg': 'x17'}, {'addr': 452316, 'reg': 'x17'}, {'addr': 452332, 'reg': 'x17'},
          {'addr': 452348, 'reg': 'x17'}, {'addr': 452364, 'reg': 'x17'}, {'addr': 452380, 'reg': 'x17'},
          {'addr': 452396, 'reg': 'x17'}, {'addr': 452412, 'reg': 'x17'}, {'addr': 452428, 'reg': 'x17'},
          {'addr': 452444, 'reg': 'x17'}, {'addr': 452460, 'reg': 'x17'}, {'addr': 452476, 'reg': 'x17'},
          {'addr': 452492, 'reg': 'x17'}, {'addr': 452508, 'reg': 'x17'}, {'addr': 452524, 'reg': 'x17'},
          {'addr': 452540, 'reg': 'x17'}, {'addr': 452556, 'reg': 'x17'}, {'addr': 452572, 'reg': 'x17'},
          {'addr': 452588, 'reg': 'x17'}, {'addr': 452604, 'reg': 'x17'}, {'addr': 452620, 'reg': 'x17'},
          {'addr': 452636, 'reg': 'x17'}, {'addr': 452652, 'reg': 'x17'}, {'addr': 452668, 'reg': 'x17'},
          {'addr': 452684, 'reg': 'x17'}, {'addr': 452700, 'reg': 'x17'}, {'addr': 452716, 'reg': 'x17'},
          {'addr': 452732, 'reg': 'x17'}, {'addr': 452748, 'reg': 'x17'}, {'addr': 452764, 'reg': 'x17'},
          {'addr': 452780, 'reg': 'x17'}, {'addr': 452796, 'reg': 'x17'}, {'addr': 452812, 'reg': 'x17'},
          {'addr': 452828, 'reg': 'x17'}, {'addr': 452844, 'reg': 'x17'}, {'addr': 453744, 'reg': 'x0'},
          {'addr': 453844, 'reg': 'x30'}, {'addr': 455040, 'reg': 'x13'}, {'addr': 455316, 'reg': 'x11'},
          {'addr': 455600, 'reg': 'x15'}, {'addr': 455880, 'reg': 'x19'}, {'addr': 456124, 'reg': 'x15'},
          {'addr': 456228, 'reg': 'x30'}, {'addr': 457184, 'reg': 'x15'}, {'addr': 458092, 'reg': 'x14'},
          {'addr': 458732, 'reg': 'x6'}, {'addr': 458968, 'reg': 'x2'}, {'addr': 461092, 'reg': 'x30'},
          {'addr': 462072, 'reg': 'x19'}, {'addr': 462328, 'reg': 'x1'}, {'addr': 463520, 'reg': 'x12'},
          {'addr': 463836, 'reg': 'x13'}, {'addr': 464132, 'reg': 'x10'}, {'addr': 464428, 'reg': 'x10'},
          {'addr': 464836, 'reg': 'x0'}, {'addr': 465088, 'reg': 'x0'}, {'addr': 465376, 'reg': 'x12'},
          {'addr': 466224, 'reg': 'x8'}, {'addr': 466492, 'reg': 'x5'}, {'addr': 466840, 'reg': 'x6'},
          {'addr': 467592, 'reg': 'x8'}, {'addr': 467620, 'reg': 'x0'}, {'addr': 468376, 'reg': 'x8'},
          {'addr': 468780, 'reg': 'x13'}, {'addr': 469064, 'reg': 'x2'}, {'addr': 470440, 'reg': 'x6'},
          {'addr': 470732, 'reg': 'x2'}, {'addr': 470804, 'reg': 'x30'}, {'addr': 471092, 'reg': 'x11'},
          {'addr': 471364, 'reg': 'x19'}, {'addr': 472948, 'reg': 'x30'}, {'addr': 473824, 'reg': 'x8'},
          {'addr': 474808, 'reg': 'x1'}, {'addr': 475080, 'reg': 'x3'}, {'addr': 475504, 'reg': 'x7'},
          {'addr': 475796, 'reg': 'x13'}, {'addr': 476184, 'reg': 'x2'}, {'addr': 476472, 'reg': 'x0'},
          {'addr': 476744, 'reg': 'x1'}, {'addr': 477016, 'reg': 'x5'}, {'addr': 477316, 'reg': 'x3'},
          {'addr': 478364, 'reg': 'x8'}, {'addr': 478472, 'reg': 'x6'}, {'addr': 478724, 'reg': 'x9'},
          {'addr': 479012, 'reg': 'x30'}, {'addr': 480892, 'reg': 'x6'}, {'addr': 480996, 'reg': 'x30'},
          {'addr': 481248, 'reg': 'x0'}, {'addr': 482724, 'reg': 'x8'}, {'addr': 483076, 'reg': 'x15'},
          {'addr': 483340, 'reg': 'x0'}, {'addr': 484256, 'reg': 'x11'}, {'addr': 484528, 'reg': 'x0'},
          {'addr': 484828, 'reg': 'x12'}, {'addr': 484984, 'reg': 'x6'}, {'addr': 485284, 'reg': 'x17'},
          {'addr': 486164, 'reg': 'x8'}, {'addr': 487132, 'reg': 'x7'}, {'addr': 487752, 'reg': 'x2'},
          {'addr': 488024, 'reg': 'x15'}, {'addr': 488284, 'reg': 'x8'}, {'addr': 489140, 'reg': 'x30'},
          {'addr': 489444, 'reg': 'x2'}, {'addr': 489948, 'reg': 'x4'}, {'addr': 490292, 'reg': 'x5'},
          {'addr': 491560, 'reg': 'x8'}, {'addr': 491668, 'reg': 'x30'}, {'addr': 493336, 'reg': 'x16'},
          {'addr': 494144, 'reg': 'x8'}, {'addr': 494472, 'reg': 'x14'}, {'addr': 495260, 'reg': 'x8'},
          {'addr': 495536, 'reg': 'x6'}, {'addr': 496244, 'reg': 'x30'}, {'addr': 496604, 'reg': 'x10'},
          {'addr': 496868, 'reg': 'x9'}, {'addr': 497188, 'reg': 'x10'}, {'addr': 499132, 'reg': 'x6'},
          {'addr': 499292, 'reg': 'x6'}, {'addr': 500344, 'reg': 'x8'}, {'addr': 500452, 'reg': 'x30'},
          {'addr': 500748, 'reg': 'x9'}, {'addr': 501144, 'reg': 'x0'}, {'addr': 501432, 'reg': 'x3'},
          {'addr': 501664, 'reg': 'x4'}, {'addr': 501928, 'reg': 'x6'}, {'addr': 502460, 'reg': 'x19'},
          {'addr': 502680, 'reg': 'x6'}, {'addr': 502984, 'reg': 'x19'}, {'addr': 503260, 'reg': 'x12'},
          {'addr': 503512, 'reg': 'x17'}, {'addr': 503936, 'reg': 'x6'}, {'addr': 504272, 'reg': 'x0'},
          {'addr': 504388, 'reg': 'x30'}, {'addr': 504708, 'reg': 'x1'}, {'addr': 504992, 'reg': 'x15'},
          {'addr': 505096, 'reg': 'x6'}, {'addr': 505348, 'reg': 'x7'}, {'addr': 506388, 'reg': 'x7'},
          {'addr': 506632, 'reg': 'x2'}, {'addr': 506884, 'reg': 'x0'}, {'addr': 507204, 'reg': 'x1'},
          {'addr': 507496, 'reg': 'x3'}, {'addr': 509872, 'reg': 'x15'}, {'addr': 510292, 'reg': 'x3'},
          {'addr': 510628, 'reg': 'x6'}, {'addr': 510972, 'reg': 'x16'}, {'addr': 511076, 'reg': 'x30'},
          {'addr': 511916, 'reg': 'x14'}, {'addr': 512236, 'reg': 'x10'}, {'addr': 514168, 'reg': 'x8'},
          {'addr': 514232, 'reg': 'x6'}, {'addr': 515284, 'reg': 'x8'}, {'addr': 515752, 'reg': 'x16'},
          {'addr': 516020, 'reg': 'x6'}, {'addr': 516704, 'reg': 'x2'}, {'addr': 517620, 'reg': 'x13'},
          {'addr': 519260, 'reg': 'x8'}, {'addr': 520776, 'reg': 'x8'}, {'addr': 521052, 'reg': 'x3'},
          {'addr': 521300, 'reg': 'x17'}, {'addr': 521576, 'reg': 'x15'}, {'addr': 521836, 'reg': 'x2'},
          {'addr': 522140, 'reg': 'x16'}, {'addr': 522292, 'reg': 'x30'}, {'addr': 522648, 'reg': 'x6'},
          {'addr': 522908, 'reg': 'x1'}, {'addr': 523908, 'reg': 'x8'}, {'addr': 523976, 'reg': 'x6'},
          {'addr': 524284, 'reg': 'x19'}, {'addr': 524392, 'reg': 'x6'}, {'addr': 524684, 'reg': 'x11'},
          {'addr': 525596, 'reg': 'x8'}, {'addr': 525644, 'reg': 'x6'}, {'addr': 526344, 'reg': 'x8'},
          {'addr': 527216, 'reg': 'x9'}, {'addr': 527316, 'reg': 'x30'}, {'addr': 528172, 'reg': 'x2'},
          {'addr': 528444, 'reg': 'x1'}, {'addr': 528780, 'reg': 'x9'}, {'addr': 529116, 'reg': 'x1'},
          {'addr': 529744, 'reg': 'x8'}, {'addr': 530012, 'reg': 'x2'}, {'addr': 531612, 'reg': 'x4'},
          {'addr': 531972, 'reg': 'x14'}, {'addr': 532240, 'reg': 'x17'}, {'addr': 532512, 'reg': 'x11'},
          {'addr': 532768, 'reg': 'x6'}, {'addr': 532916, 'reg': 'x30'}, {'addr': 533268, 'reg': 'x10'},
          {'addr': 533556, 'reg': 'x7'}, {'addr': 533820, 'reg': 'x8'}, {'addr': 534232, 'reg': 'x6'},
          {'addr': 535336, 'reg': 'x8'}, {'addr': 535628, 'reg': 'x14'}, {'addr': 536368, 'reg': 'x8'},
          {'addr': 537692, 'reg': 'x14'}, {'addr': 538604, 'reg': 'x8'}, {'addr': 540180, 'reg': 'x6'},
          {'addr': 541128, 'reg': 'x8'}, {'addr': 542020, 'reg': 'x30'}, {'addr': 542380, 'reg': 'x5'},
          {'addr': 542652, 'reg': 'x16'}, {'addr': 544188, 'reg': 'x8'}, {'addr': 545636, 'reg': 'x8'},
          {'addr': 546816, 'reg': 'x8'}, {'addr': 547664, 'reg': 'x8'}, {'addr': 547916, 'reg': 'x1'},
          {'addr': 548584, 'reg': 'x8'}, {'addr': 549548, 'reg': 'x6'}, {'addr': 549992, 'reg': 'x16'},
          {'addr': 550020, 'reg': 'x6'}, {'addr': 550260, 'reg': 'x30'}, {'addr': 550644, 'reg': 'x17'},
          {'addr': 551436, 'reg': 'x7'}, {'addr': 551624, 'reg': 'x6'}, {'addr': 552552, 'reg': 'x7'},
          {'addr': 552816, 'reg': 'x15'}, {'addr': 553144, 'reg': 'x8'}, {'addr': 553428, 'reg': 'x8'},
          {'addr': 553712, 'reg': 'x10'}, {'addr': 553996, 'reg': 'x5'}, {'addr': 554272, 'reg': 'x6'},
          {'addr': 555492, 'reg': 'x3'}, {'addr': 555944, 'reg': 'x15'}, {'addr': 557624, 'reg': 'x6'},
          {'addr': 557956, 'reg': 'x10'}, {'addr': 558272, 'reg': 'x13'}, {'addr': 558552, 'reg': 'x5'},
          {'addr': 558792, 'reg': 'x10'}, {'addr': 559076, 'reg': 'x17'}, {'addr': 559472, 'reg': 'x7'},
          {'addr': 559620, 'reg': 'x30'}, {'addr': 560232, 'reg': 'x3'}, {'addr': 560524, 'reg': 'x7'},
          {'addr': 560816, 'reg': 'x19'}, {'addr': 561092, 'reg': 'x8'}, {'addr': 561352, 'reg': 'x15'},
          {'addr': 561624, 'reg': 'x3'}, {'addr': 561672, 'reg': 'x6'}, {'addr': 561940, 'reg': 'x15'},
          {'addr': 562284, 'reg': 'x10'}, {'addr': 563224, 'reg': 'x8'}, {'addr': 564388, 'reg': 'x17'},
          {'addr': 564484, 'reg': 'x30'}, {'addr': 564744, 'reg': 'x6'}, {'addr': 565040, 'reg': 'x13'},
          {'addr': 565312, 'reg': 'x19'}, {'addr': 565572, 'reg': 'x8'}, {'addr': 565796, 'reg': 'x30'},
          {'addr': 566108, 'reg': 'x8'}, {'addr': 567572, 'reg': 'x8'}, {'addr': 567920, 'reg': 'x10'},
          {'addr': 568020, 'reg': 'x30'}, {'addr': 568320, 'reg': 'x19'}, {'addr': 568592, 'reg': 'x4'},
          {'addr': 570772, 'reg': 'x8'}, {'addr': 571108, 'reg': 'x16'}, {'addr': 571472, 'reg': 'x9'},
          {'addr': 571892, 'reg': 'x8'}, {'addr': 572116, 'reg': 'x6'}, {'addr': 572392, 'reg': 'x19'},
          {'addr': 572896, 'reg': 'x8'}, {'addr': 573172, 'reg': 'x7'}, {'addr': 573536, 'reg': 'x16'},
          {'addr': 573856, 'reg': 'x11'}, {'addr': 574888, 'reg': 'x9'}, {'addr': 575968, 'reg': 'x8'},
          {'addr': 576352, 'reg': 'x19'}, {'addr': 577108, 'reg': 'x8'}, {'addr': 577388, 'reg': 'x2'},
          {'addr': 577708, 'reg': 'x16'}, {'addr': 578052, 'reg': 'x17'}, {'addr': 578148, 'reg': 'x30'},
          {'addr': 578272, 'reg': 'x6'}, {'addr': 578728, 'reg': 'x12'}, {'addr': 579036, 'reg': 'x0'},
          {'addr': 582204, 'reg': 'x8'}, {'addr': 582508, 'reg': 'x9'}, {'addr': 582804, 'reg': 'x6'},
          {'addr': 583092, 'reg': 'x3'}, {'addr': 583456, 'reg': 'x9'}, {'addr': 583940, 'reg': 'x0'},
          {'addr': 584772, 'reg': 'x8'}, {'addr': 585060, 'reg': 'x8'}, {'addr': 585544, 'reg': 'x12'},
          {'addr': 585808, 'reg': 'x12'}, {'addr': 585908, 'reg': 'x30'}, {'addr': 587232, 'reg': 'x8'},
          {'addr': 587520, 'reg': 'x0'}, {'addr': 587796, 'reg': 'x15'}, {'addr': 588224, 'reg': 'x17'},
          {'addr': 588676, 'reg': 'x15'}, {'addr': 588988, 'reg': 'x17'}, {'addr': 589092, 'reg': 'x30'},
          {'addr': 589540, 'reg': 'x4'}, {'addr': 589592, 'reg': 'x6'}, {'addr': 589684, 'reg': 'x30'},
          {'addr': 589928, 'reg': 'x9'}, {'addr': 590796, 'reg': 'x2'}, {'addr': 591148, 'reg': 'x1'},
          {'addr': 591440, 'reg': 'x12'}, {'addr': 592452, 'reg': 'x6'}, {'addr': 592848, 'reg': 'x6'},
          {'addr': 593336, 'reg': 'x3'}, {'addr': 593632, 'reg': 'x2'}, {'addr': 593896, 'reg': 'x11'},
          {'addr': 594208, 'reg': 'x19'}, {'addr': 595028, 'reg': 'x6'}, {'addr': 595856, 'reg': 'x15'},
          {'addr': 596144, 'reg': 'x8'}, {'addr': 596428, 'reg': 'x9'}, {'addr': 597204, 'reg': 'x30'},
          {'addr': 597552, 'reg': 'x7'}, {'addr': 597904, 'reg': 'x19'}, {'addr': 598820, 'reg': 'x8'},
          {'addr': 599108, 'reg': 'x8'}, {'addr': 601048, 'reg': 'x13'}, {'addr': 601412, 'reg': 'x0'},
          {'addr': 602620, 'reg': 'x8'}, {'addr': 602972, 'reg': 'x1'}, {'addr': 603268, 'reg': 'x5'},
          {'addr': 603320, 'reg': 'x6'}, {'addr': 603576, 'reg': 'x2'}, {'addr': 603848, 'reg': 'x14'},
          {'addr': 606412, 'reg': 'x8'}, {'addr': 606704, 'reg': 'x14'}, {'addr': 606988, 'reg': 'x2'},
          {'addr': 608820, 'reg': 'x30'}, {'addr': 609080, 'reg': 'x3'}, {'addr': 609428, 'reg': 'x2'},
          {'addr': 609672, 'reg': 'x15'}, {'addr': 610172, 'reg': 'x19'}, {'addr': 610620, 'reg': 'x3'},
          {'addr': 610912, 'reg': 'x10'}, {'addr': 610968, 'reg': 'x6'}, {'addr': 611060, 'reg': 'x30'},
          {'addr': 611348, 'reg': 'x7'}, {'addr': 611620, 'reg': 'x19'}, {'addr': 612596, 'reg': 'x16'},
          {'addr': 613708, 'reg': 'x6'}, {'addr': 614676, 'reg': 'x8'}, {'addr': 615480, 'reg': 'x2'},
          {'addr': 615572, 'reg': 'x30'}, {'addr': 615860, 'reg': 'x2'}, {'addr': 616900, 'reg': 'x30'},
          {'addr': 617212, 'reg': 'x7'}, {'addr': 617320, 'reg': 'x6'}, {'addr': 617644, 'reg': 'x6'},
          {'addr': 618536, 'reg': 'x8'}, {'addr': 619824, 'reg': 'x12'}, {'addr': 620148, 'reg': 'x30'},
          {'addr': 621068, 'reg': 'x8'}, {'addr': 623124, 'reg': 'x30'}, {'addr': 623220, 'reg': 'x30'},
          {'addr': 623476, 'reg': 'x6'}, {'addr': 623784, 'reg': 'x6'}, {'addr': 624232, 'reg': 'x16'},
          {'addr': 624496, 'reg': 'x16'}, {'addr': 626244, 'reg': 'x8'}, {'addr': 626576, 'reg': 'x13'},
          {'addr': 626884, 'reg': 'x13'}, {'addr': 627184, 'reg': 'x14'}, {'addr': 627464, 'reg': 'x15'},
          {'addr': 627804, 'reg': 'x7'}, {'addr': 629196, 'reg': 'x8'}, {'addr': 629588, 'reg': 'x13'},
          {'addr': 629924, 'reg': 'x9'}, {'addr': 630252, 'reg': 'x6'}, {'addr': 631436, 'reg': 'x8'},
          {'addr': 631704, 'reg': 'x2'}, {'addr': 631992, 'reg': 'x17'}, {'addr': 632516, 'reg': 'x30'},
          {'addr': 632836, 'reg': 'x16'}, {'addr': 633112, 'reg': 'x0'}, {'addr': 633356, 'reg': 'x10'},
          {'addr': 633772, 'reg': 'x13'}, {'addr': 634160, 'reg': 'x0'}, {'addr': 634452, 'reg': 'x9'},
          {'addr': 634748, 'reg': 'x19'}, {'addr': 635012, 'reg': 'x19'}, {'addr': 635284, 'reg': 'x0'},
          {'addr': 636064, 'reg': 'x8'}, {'addr': 636380, 'reg': 'x6'}, {'addr': 636792, 'reg': 'x6'},
          {'addr': 637172, 'reg': 'x1'}, {'addr': 637552, 'reg': 'x5'}, {'addr': 637820, 'reg': 'x9'},
          {'addr': 638120, 'reg': 'x6'}, {'addr': 638420, 'reg': 'x12'}, {'addr': 639024, 'reg': 'x8'},
          {'addr': 640124, 'reg': 'x8'}, {'addr': 640456, 'reg': 'x17'}, {'addr': 640468, 'reg': 'x30'},
          {'addr': 641388, 'reg': 'x10'}, {'addr': 642276, 'reg': 'x19'}, {'addr': 644092, 'reg': 'x8'},
          {'addr': 644656, 'reg': 'x6'}, {'addr': 645012, 'reg': 'x4'}, {'addr': 645336, 'reg': 'x19'},
          {'addr': 645776, 'reg': 'x11'}, {'addr': 645832, 'reg': 'x6'}, {'addr': 646092, 'reg': 'x0'},
          {'addr': 646200, 'reg': 'x6'}, {'addr': 646540, 'reg': 'x11'}, {'addr': 646840, 'reg': 'x7'},
          {'addr': 648280, 'reg': 'x15'}, {'addr': 648696, 'reg': 'x19'}, {'addr': 648836, 'reg': 'x30'},
          {'addr': 649092, 'reg': 'x14'}, {'addr': 649356, 'reg': 'x2'}, {'addr': 650368, 'reg': 'x19'},
          {'addr': 650516, 'reg': 'x30'}, {'addr': 650760, 'reg': 'x10'}, {'addr': 651700, 'reg': 'x12'},
          {'addr': 651996, 'reg': 'x7'}, {'addr': 652288, 'reg': 'x17'}, {'addr': 653432, 'reg': 'x4'},
          {'addr': 653784, 'reg': 'x5'}, {'addr': 654056, 'reg': 'x3'}, {'addr': 656412, 'reg': 'x8'},
          {'addr': 657496, 'reg': 'x3'}, {'addr': 657852, 'reg': 'x8'}, {'addr': 659872, 'reg': 'x8'},
          {'addr': 660572, 'reg': 'x6'}, {'addr': 661012, 'reg': 'x12'}, {'addr': 661480, 'reg': 'x6'},
          {'addr': 662496, 'reg': 'x8'}, {'addr': 662764, 'reg': 'x4'}, {'addr': 663728, 'reg': 'x0'},
          {'addr': 664940, 'reg': 'x6'}, {'addr': 665216, 'reg': 'x19'}, {'addr': 665780, 'reg': 'x30'},
          {'addr': 666868, 'reg': 'x16'}, {'addr': 667120, 'reg': 'x3'}, {'addr': 667400, 'reg': 'x15'},
          {'addr': 667652, 'reg': 'x12'}, {'addr': 670596, 'reg': 'x8'}, {'addr': 670868, 'reg': 'x3'},
          {'addr': 672572, 'reg': 'x3'}, {'addr': 672900, 'reg': 'x5'}, {'addr': 673516, 'reg': 'x8'},
          {'addr': 674496, 'reg': 'x8'}, {'addr': 675124, 'reg': 'x6'}, {'addr': 675448, 'reg': 'x15'},
          {'addr': 675720, 'reg': 'x16'}, {'addr': 676008, 'reg': 'x0'}, {'addr': 676824, 'reg': 'x8'},
          {'addr': 677136, 'reg': 'x4'}, {'addr': 678472, 'reg': 'x7'}, {'addr': 679284, 'reg': 'x19'},
          {'addr': 679560, 'reg': 'x15'}, {'addr': 679912, 'reg': 'x6'}, {'addr': 680304, 'reg': 'x13'},
          {'addr': 681104, 'reg': 'x8'}, {'addr': 683016, 'reg': 'x3'}, {'addr': 683284, 'reg': 'x12'},
          {'addr': 683556, 'reg': 'x19'}, {'addr': 683800, 'reg': 'x1'}, {'addr': 684080, 'reg': 'x4'},
          {'addr': 684404, 'reg': 'x12'}, {'addr': 684792, 'reg': 'x4'}, {'addr': 685340, 'reg': 'x15'},
          {'addr': 685612, 'reg': 'x12'}, {'addr': 686484, 'reg': 'x6'}, {'addr': 687620, 'reg': 'x10'},
          {'addr': 687864, 'reg': 'x11'}, {'addr': 689036, 'reg': 'x0'}, {'addr': 689412, 'reg': 'x8'},
          {'addr': 690328, 'reg': 'x8'}, {'addr': 690832, 'reg': 'x9'}, {'addr': 691108, 'reg': 'x12'},
          {'addr': 692020, 'reg': 'x8'}, {'addr': 692916, 'reg': 'x6'}, {'addr': 693188, 'reg': 'x11'},
          {'addr': 693744, 'reg': 'x6'}, {'addr': 694028, 'reg': 'x13'}, {'addr': 694396, 'reg': 'x17'},
          {'addr': 694500, 'reg': 'x30'}, {'addr': 694804, 'reg': 'x4'}, {'addr': 695116, 'reg': 'x17'},
          {'addr': 695400, 'reg': 'x14'}, {'addr': 695704, 'reg': 'x8'}, {'addr': 695796, 'reg': 'x30'},
          {'addr': 696868, 'reg': 'x13'}, {'addr': 697760, 'reg': 'x8'}, {'addr': 698196, 'reg': 'x11'},
          {'addr': 698696, 'reg': 'x14'}, {'addr': 699632, 'reg': 'x8'}, {'addr': 700612, 'reg': 'x4'},
          {'addr': 700912, 'reg': 'x6'}, {'addr': 701272, 'reg': 'x4'}, {'addr': 701660, 'reg': 'x4'},
          {'addr': 701764, 'reg': 'x30'}, {'addr': 702048, 'reg': 'x10'}, {'addr': 702320, 'reg': 'x11'},
          {'addr': 703224, 'reg': 'x6'}, {'addr': 703316, 'reg': 'x30'}, {'addr': 704172, 'reg': 'x15'},
          {'addr': 704464, 'reg': 'x1'}, {'addr': 705252, 'reg': 'x30'}, {'addr': 705460, 'reg': 'x30'},
          {'addr': 705708, 'reg': 'x19'}, {'addr': 707140, 'reg': 'x9'}, {'addr': 708384, 'reg': 'x8'},
          {'addr': 709448, 'reg': 'x6'}, {'addr': 710552, 'reg': 'x10'}, {'addr': 710740, 'reg': 'x30'},
          {'addr': 712340, 'reg': 'x9'}, {'addr': 713260, 'reg': 'x19'}, {'addr': 713596, 'reg': 'x15'},
          {'addr': 714476, 'reg': 'x9'}, {'addr': 714752, 'reg': 'x5'}, {'addr': 714852, 'reg': 'x30'},
          {'addr': 715832, 'reg': 'x7'}, {'addr': 716928, 'reg': 'x3'}, {'addr': 717256, 'reg': 'x10'},
          {'addr': 717496, 'reg': 'x6'}, {'addr': 717824, 'reg': 'x13'}, {'addr': 718124, 'reg': 'x19'},
          {'addr': 718916, 'reg': 'x8'}, {'addr': 719772, 'reg': 'x8'}, {'addr': 720044, 'reg': 'x12'},
          {'addr': 720900, 'reg': 'x6'}, {'addr': 721604, 'reg': 'x6'}, {'addr': 721976, 'reg': 'x17'},
          {'addr': 722256, 'reg': 'x3'}, {'addr': 722800, 'reg': 'x9'}, {'addr': 723060, 'reg': 'x14'},
          {'addr': 723252, 'reg': 'x30'}, {'addr': 724308, 'reg': 'x6'}, {'addr': 724892, 'reg': 'x8'},
          {'addr': 726380, 'reg': 'x8'}, {'addr': 726824, 'reg': 'x15'}, {'addr': 727136, 'reg': 'x1'},
          {'addr': 727176, 'reg': 'x6'}, {'addr': 727588, 'reg': 'x7'}, {'addr': 729540, 'reg': 'x19'},
          {'addr': 729904, 'reg': 'x1'}, {'addr': 731464, 'reg': 'x8'}, {'addr': 731748, 'reg': 'x19'},
          {'addr': 732132, 'reg': 'x0'}, {'addr': 733016, 'reg': 'x8'}, {'addr': 733344, 'reg': 'x7'},
          {'addr': 733812, 'reg': 'x12'}, {'addr': 736336, 'reg': 'x11'}, {'addr': 736720, 'reg': 'x1'},
          {'addr': 736868, 'reg': 'x30'}, {'addr': 737256, 'reg': 'x2'}, {'addr': 738288, 'reg': 'x3'},
          {'addr': 739048, 'reg': 'x8'}, {'addr': 739384, 'reg': 'x19'}, {'addr': 740436, 'reg': 'x14'},
          {'addr': 740532, 'reg': 'x6'}, {'addr': 741360, 'reg': 'x8'}, {'addr': 741664, 'reg': 'x14'},
          {'addr': 741944, 'reg': 'x8'}, {'addr': 742204, 'reg': 'x14'}, {'addr': 742520, 'reg': 'x13'},
          {'addr': 742796, 'reg': 'x11'}, {'addr': 743996, 'reg': 'x5'}, {'addr': 744396, 'reg': 'x13'},
          {'addr': 745084, 'reg': 'x8'}, {'addr': 745876, 'reg': 'x8'}, {'addr': 746184, 'reg': 'x7'},
          {'addr': 747004, 'reg': 'x8'}, {'addr': 747268, 'reg': 'x12'}, {'addr': 748196, 'reg': 'x8'},
          {'addr': 749172, 'reg': 'x30'}, {'addr': 749732, 'reg': 'x8'}, {'addr': 750020, 'reg': 'x15'},
          {'addr': 751464, 'reg': 'x8'}, {'addr': 751744, 'reg': 'x4'}, {'addr': 752668, 'reg': 'x8'},
          {'addr': 754060, 'reg': 'x8'}, {'addr': 754328, 'reg': 'x5'}, {'addr': 754596, 'reg': 'x12'},
          {'addr': 754692, 'reg': 'x30'}, {'addr': 754964, 'reg': 'x19'}, {'addr': 755232, 'reg': 'x3'},
          {'addr': 756000, 'reg': 'x7'}, {'addr': 756328, 'reg': 'x13'}, {'addr': 756632, 'reg': 'x4'},
          {'addr': 758584, 'reg': 'x8'}, {'addr': 759028, 'reg': 'x16'}, {'addr': 759288, 'reg': 'x6'},
          {'addr': 759584, 'reg': 'x12'}, {'addr': 760192, 'reg': 'x2'}, {'addr': 760492, 'reg': 'x11'},
          {'addr': 760776, 'reg': 'x1'}, {'addr': 762404, 'reg': 'x2'}, {'addr': 762808, 'reg': 'x19'},
          {'addr': 763804, 'reg': 'x3'}, {'addr': 764136, 'reg': 'x14'}, {'addr': 765108, 'reg': 'x8'},
          {'addr': 765388, 'reg': 'x17'}, {'addr': 766428, 'reg': 'x8'}, {'addr': 766756, 'reg': 'x6'},
          {'addr': 770824, 'reg': 'x8'}, {'addr': 771920, 'reg': 'x14'}, {'addr': 772020, 'reg': 'x30'},
          {'addr': 773232, 'reg': 'x0'}, {'addr': 773492, 'reg': 'x6'}, {'addr': 774788, 'reg': 'x19'},
          {'addr': 774820, 'reg': 'x6'}, {'addr': 775136, 'reg': 'x2'}, {'addr': 776392, 'reg': 'x7'},
          {'addr': 776800, 'reg': 'x16'}, {'addr': 777448, 'reg': 'x6'}, {'addr': 777724, 'reg': 'x13'},
          {'addr': 778112, 'reg': 'x6'}, {'addr': 778560, 'reg': 'x5'}, {'addr': 779260, 'reg': 'x8'},
          {'addr': 780412, 'reg': 'x6'}, {'addr': 780696, 'reg': 'x1'}, {'addr': 780964, 'reg': 'x13'},
          {'addr': 781396, 'reg': 'x1'}, {'addr': 781660, 'reg': 'x14'}, {'addr': 782556, 'reg': 'x15'},
          {'addr': 784044, 'reg': 'x8'}, {'addr': 784256, 'reg': 'x6'}, {'addr': 784552, 'reg': 'x11'},
          {'addr': 784836, 'reg': 'x11'}, {'addr': 785492, 'reg': 'x30'}, {'addr': 785780, 'reg': 'x9'},
          {'addr': 786152, 'reg': 'x11'}, {'addr': 786428, 'reg': 'x0'}, {'addr': 786692, 'reg': 'x19'},
          {'addr': 786972, 'reg': 'x6'}, {'addr': 788344, 'reg': 'x8'}, {'addr': 788636, 'reg': 'x1'},
          {'addr': 790356, 'reg': 'x8'}, {'addr': 790948, 'reg': 'x5'}, {'addr': 791336, 'reg': 'x6'},
          {'addr': 791428, 'reg': 'x30'}, {'addr': 794964, 'reg': 'x8'}, {'addr': 795244, 'reg': 'x12'},
          {'addr': 795640, 'reg': 'x11'}, {'addr': 796100, 'reg': 'x8'}, {'addr': 796448, 'reg': 'x17'},
          {'addr': 796744, 'reg': 'x14'}, {'addr': 796996, 'reg': 'x9'}, {'addr': 797432, 'reg': 'x10'},
          {'addr': 798772, 'reg': 'x19'}, {'addr': 799096, 'reg': 'x17'}, {'addr': 799432, 'reg': 'x1'},
          {'addr': 799680, 'reg': 'x14'}, {'addr': 802372, 'reg': 'x30'}, {'addr': 802656, 'reg': 'x13'},
          {'addr': 802972, 'reg': 'x5'}, {'addr': 803224, 'reg': 'x6'}, {'addr': 804016, 'reg': 'x17'},
          {'addr': 804336, 'reg': 'x10'}, {'addr': 805372, 'reg': 'x0'}, {'addr': 806232, 'reg': 'x1'},
          {'addr': 806324, 'reg': 'x30'}, {'addr': 806572, 'reg': 'x17'}, {'addr': 807460, 'reg': 'x6'},
          {'addr': 807896, 'reg': 'x6'}, {'addr': 808228, 'reg': 'x17'}, {'addr': 808588, 'reg': 'x11'},
          {'addr': 808956, 'reg': 'x3'}, {'addr': 809996, 'reg': 'x3'}, {'addr': 810332, 'reg': 'x17'},
          {'addr': 810604, 'reg': 'x3'}, {'addr': 811020, 'reg': 'x3'}, {'addr': 811320, 'reg': 'x13'},
          {'addr': 811656, 'reg': 'x17'}, {'addr': 811964, 'reg': 'x0'}, {'addr': 812072, 'reg': 'x6'},
          {'addr': 812904, 'reg': 'x8'}, {'addr': 813012, 'reg': 'x30'}, {'addr': 813760, 'reg': 'x8'},
          {'addr': 815448, 'reg': 'x6'}, {'addr': 815984, 'reg': 'x15'}, {'addr': 816288, 'reg': 'x3'},
          {'addr': 816572, 'reg': 'x15'}, {'addr': 816856, 'reg': 'x6'}, {'addr': 817276, 'reg': 'x3'},
          {'addr': 818304, 'reg': 'x15'}, {'addr': 818644, 'reg': 'x30'}, {'addr': 818852, 'reg': 'x30'},
          {'addr': 818996, 'reg': 'x30'}, {'addr': 819988, 'reg': 'x8'}, {'addr': 820220, 'reg': 'x10'},
          {'addr': 820996, 'reg': 'x30'}, {'addr': 821092, 'reg': 'x30'}, {'addr': 821108, 'reg': 'x17'},
          {'addr': 821368, 'reg': 'x8'}, {'addr': 822352, 'reg': 'x9'}, {'addr': 822772, 'reg': 'x10'},
          {'addr': 823108, 'reg': 'x19'}, {'addr': 823256, 'reg': 'x6'}, {'addr': 823560, 'reg': 'x10'},
          {'addr': 824152, 'reg': 'x8'}, {'addr': 825584, 'reg': 'x4'}, {'addr': 826508, 'reg': 'x11'},
          {'addr': 826792, 'reg': 'x4'}, {'addr': 827144, 'reg': 'x13'}, {'addr': 828076, 'reg': 'x8'},
          {'addr': 829004, 'reg': 'x13'}, {'addr': 830620, 'reg': 'x8'}, {'addr': 831420, 'reg': 'x8'},
          {'addr': 832540, 'reg': 'x8'}, {'addr': 832580, 'reg': 'x6'}, {'addr': 832928, 'reg': 'x11'},
          {'addr': 833192, 'reg': 'x6'}, {'addr': 833460, 'reg': 'x1'}, {'addr': 833740, 'reg': 'x1'},
          {'addr': 835412, 'reg': 'x8'}, {'addr': 836188, 'reg': 'x8'}, {'addr': 836436, 'reg': 'x13'},
          {'addr': 836832, 'reg': 'x2'}, {'addr': 837736, 'reg': 'x8'}, {'addr': 838036, 'reg': 'x8'},
          {'addr': 838312, 'reg': 'x8'}, {'addr': 838664, 'reg': 'x6'}, {'addr': 840096, 'reg': 'x16'},
          {'addr': 841060, 'reg': 'x15'}, {'addr': 843808, 'reg': 'x16'}, {'addr': 844068, 'reg': 'x11'},
          {'addr': 844452, 'reg': 'x4'}, {'addr': 845828, 'reg': 'x8'}, {'addr': 846136, 'reg': 'x13'},
          {'addr': 846324, 'reg': 'x30'}, {'addr': 846596, 'reg': 'x17'}, {'addr': 847600, 'reg': 'x10'},
          {'addr': 847912, 'reg': 'x19'}, {'addr': 848172, 'reg': 'x6'}, {'addr': 848476, 'reg': 'x9'},
          {'addr': 848784, 'reg': 'x11'}, {'addr': 849068, 'reg': 'x10'}, {'addr': 849544, 'reg': 'x4'},
          {'addr': 849636, 'reg': 'x30'}, {'addr': 850660, 'reg': 'x6'}, {'addr': 851608, 'reg': 'x8'},
          {'addr': 852044, 'reg': 'x7'}, {'addr': 852332, 'reg': 'x9'}, {'addr': 852744, 'reg': 'x5'},
          {'addr': 853224, 'reg': 'x5'}, {'addr': 853492, 'reg': 'x13'}, {'addr': 853804, 'reg': 'x8'},
          {'addr': 854088, 'reg': 'x1'}, {'addr': 855004, 'reg': 'x0'}, {'addr': 855268, 'reg': 'x15'},
          {'addr': 856380, 'reg': 'x8'}, {'addr': 856700, 'reg': 'x17'}, {'addr': 857008, 'reg': 'x13'},
          {'addr': 857620, 'reg': 'x8'}, {'addr': 857672, 'reg': 'x6'}, {'addr': 857936, 'reg': 'x6'},
          {'addr': 858864, 'reg': 'x9'}, {'addr': 859832, 'reg': 'x8'}, {'addr': 864724, 'reg': 'x16'},
          {'addr': 865036, 'reg': 'x19'}, {'addr': 865648, 'reg': 'x6'}, {'addr': 866532, 'reg': 'x7'},
          {'addr': 866868, 'reg': 'x16'}, {'addr': 867812, 'reg': 'x8'}, {'addr': 869384, 'reg': 'x17'},
          {'addr': 869704, 'reg': 'x16'}, {'addr': 869984, 'reg': 'x9'}, {'addr': 870948, 'reg': 'x15'},
          {'addr': 871388, 'reg': 'x4'}, {'addr': 872472, 'reg': 'x10'}, {'addr': 872852, 'reg': 'x11'},
          {'addr': 873152, 'reg': 'x11'}, {'addr': 873436, 'reg': 'x6'}, {'addr': 874364, 'reg': 'x3'},
          {'addr': 874804, 'reg': 'x3'}, {'addr': 875152, 'reg': 'x3'}, {'addr': 875452, 'reg': 'x5'},
          {'addr': 875816, 'reg': 'x3'}, {'addr': 876100, 'reg': 'x13'}, {'addr': 876368, 'reg': 'x9'},
          {'addr': 876696, 'reg': 'x0'}, {'addr': 877304, 'reg': 'x6'}, {'addr': 877840, 'reg': 'x1'},
          {'addr': 878816, 'reg': 'x5'}, {'addr': 879756, 'reg': 'x8'}, {'addr': 880064, 'reg': 'x16'},
          {'addr': 881128, 'reg': 'x8'}, {'addr': 881300, 'reg': 'x30'}, {'addr': 881732, 'reg': 'x15'},
          {'addr': 881984, 'reg': 'x1'}, {'addr': 882820, 'reg': 'x8'}, {'addr': 882936, 'reg': 'x6'},
          {'addr': 883228, 'reg': 'x17'}, {'addr': 884100, 'reg': 'x8'}, {'addr': 884796, 'reg': 'x8'},
          {'addr': 885160, 'reg': 'x17'}, {'addr': 886124, 'reg': 'x8'}, {'addr': 886424, 'reg': 'x16'},
          {'addr': 886700, 'reg': 'x8'}, {'addr': 886980, 'reg': 'x6'}, {'addr': 887300, 'reg': 'x1'},
          {'addr': 887576, 'reg': 'x5'}, {'addr': 888584, 'reg': 'x8'}, {'addr': 888868, 'reg': 'x15'},
          {'addr': 889260, 'reg': 'x8'}, {'addr': 889284, 'reg': 'x30'}, {'addr': 889548, 'reg': 'x2'},
          {'addr': 890932, 'reg': 'x13'}, {'addr': 891352, 'reg': 'x2'}, {'addr': 891624, 'reg': 'x8'},
          {'addr': 891888, 'reg': 'x11'}, {'addr': 893416, 'reg': 'x6'}, {'addr': 893736, 'reg': 'x14'},
          {'addr': 894560, 'reg': 'x8'}, {'addr': 895984, 'reg': 'x8'}, {'addr': 896280, 'reg': 'x6'},
          {'addr': 896436, 'reg': 'x30'}, {'addr': 896752, 'reg': 'x15'}, {'addr': 897124, 'reg': 'x12'},
          {'addr': 897920, 'reg': 'x8'}, {'addr': 899040, 'reg': 'x8'}, {'addr': 900572, 'reg': 'x8'},
          {'addr': 900728, 'reg': 'x6'}, {'addr': 901036, 'reg': 'x1'}, {'addr': 901768, 'reg': 'x10'},
          {'addr': 902588, 'reg': 'x8'}, {'addr': 902844, 'reg': 'x8'}, {'addr': 903168, 'reg': 'x12'},
          {'addr': 904672, 'reg': 'x10'}, {'addr': 904956, 'reg': 'x13'}, {'addr': 907544, 'reg': 'x8'},
          {'addr': 908748, 'reg': 'x14'}, {'addr': 909060, 'reg': 'x11'}, {'addr': 909920, 'reg': 'x8'},
          {'addr': 910220, 'reg': 'x17'}, {'addr': 910624, 'reg': 'x8'}, {'addr': 911208, 'reg': 'x14'},
          {'addr': 911680, 'reg': 'x30'}, {'addr': 912648, 'reg': 'x5'}, {'addr': 913120, 'reg': 'x7'},
          {'addr': 913440, 'reg': 'x5'}, {'addr': 913768, 'reg': 'x3'}, {'addr': 914032, 'reg': 'x8'},
          {'addr': 915008, 'reg': 'x8'}, {'addr': 916044, 'reg': 'x8'}, {'addr': 920364, 'reg': 'x8'},
          {'addr': 920664, 'reg': 'x6'}, {'addr': 920932, 'reg': 'x7'}, {'addr': 921272, 'reg': 'x14'},
          {'addr': 922492, 'reg': 'x19'}, {'addr': 923000, 'reg': 'x7'}, {'addr': 924052, 'reg': 'x8'},
          {'addr': 924164, 'reg': 'x30'}, {'addr': 924884, 'reg': 'x30'}, {'addr': 925168, 'reg': 'x16'},
          {'addr': 925948, 'reg': 'x8'}, {'addr': 926140, 'reg': 'x6'}, {'addr': 927688, 'reg': 'x0'},
          {'addr': 927956, 'reg': 'x6'}, {'addr': 928324, 'reg': 'x10'}, {'addr': 928612, 'reg': 'x17'},
          {'addr': 929136, 'reg': 'x1'}, {'addr': 930656, 'reg': 'x8'}, {'addr': 930712, 'reg': 'x6'},
          {'addr': 931088, 'reg': 'x3'}, {'addr': 931380, 'reg': 'x11'}, {'addr': 931640, 'reg': 'x8'},
          {'addr': 931924, 'reg': 'x15'}, {'addr': 932196, 'reg': 'x6'}, {'addr': 932448, 'reg': 'x7'},
          {'addr': 932700, 'reg': 'x11'}, {'addr': 933160, 'reg': 'x13'}, {'addr': 934028, 'reg': 'x8'},
          {'addr': 935040, 'reg': 'x10'}, {'addr': 935320, 'reg': 'x9'}, {'addr': 935996, 'reg': 'x8'},
          {'addr': 936272, 'reg': 'x16'}, {'addr': 937144, 'reg': 'x8'}, {'addr': 937408, 'reg': 'x14'},
          {'addr': 939340, 'reg': 'x8'}, {'addr': 939668, 'reg': 'x10'}, {'addr': 940880, 'reg': 'x8'},
          {'addr': 941680, 'reg': 'x8'}, {'addr': 941936, 'reg': 'x6'}, {'addr': 942228, 'reg': 'x6'},
          {'addr': 943732, 'reg': 'x15'}, {'addr': 944084, 'reg': 'x0'}, {'addr': 944436, 'reg': 'x16'},
          {'addr': 944696, 'reg': 'x1'}, {'addr': 945644, 'reg': 'x8'}, {'addr': 945928, 'reg': 'x0'},
          {'addr': 946704, 'reg': 'x6'}, {'addr': 946984, 'reg': 'x5'}, {'addr': 947240, 'reg': 'x19'},
          {'addr': 947548, 'reg': 'x7'}, {'addr': 947816, 'reg': 'x15'}, {'addr': 948144, 'reg': 'x9'},
          {'addr': 948244, 'reg': 'x30'}, {'addr': 948580, 'reg': 'x11'}, {'addr': 948876, 'reg': 'x11'},
          {'addr': 950380, 'reg': 'x6'}, {'addr': 950656, 'reg': 'x14'}, {'addr': 950924, 'reg': 'x16'},
          {'addr': 951404, 'reg': 'x2'}, {'addr': 951672, 'reg': 'x1'}, {'addr': 952632, 'reg': 'x17'},
          {'addr': 952948, 'reg': 'x30'}, {'addr': 953264, 'reg': 'x5'}, {'addr': 954120, 'reg': 'x8'},
          {'addr': 954412, 'reg': 'x17'}, {'addr': 954676, 'reg': 'x5'}, {'addr': 954964, 'reg': 'x5'},
          {'addr': 954980, 'reg': 'x30'}, {'addr': 955488, 'reg': 'x5'}, {'addr': 955812, 'reg': 'x4'},
          {'addr': 956400, 'reg': 'x6'}, {'addr': 956748, 'reg': 'x16'}, {'addr': 956844, 'reg': 'x30'},
          {'addr': 958176, 'reg': 'x8'}, {'addr': 958424, 'reg': 'x16'}, {'addr': 958612, 'reg': 'x30'},
          {'addr': 959804, 'reg': 'x8'}, {'addr': 959984, 'reg': 'x6'}, {'addr': 960308, 'reg': 'x6'},
          {'addr': 960644, 'reg': 'x2'}, {'addr': 960960, 'reg': 'x1'}, {'addr': 961484, 'reg': 'x10'},
          {'addr': 963320, 'reg': 'x8'}, {'addr': 963420, 'reg': 'x30'}, {'addr': 964424, 'reg': 'x1'},
          {'addr': 965352, 'reg': 'x7'}, {'addr': 965744, 'reg': 'x6'}, {'addr': 966840, 'reg': 'x12'},
          {'addr': 967088, 'reg': 'x0'}, {'addr': 967404, 'reg': 'x17'}, {'addr': 967848, 'reg': 'x6'},
          {'addr': 968148, 'reg': 'x11'}, {'addr': 969232, 'reg': 'x3'}, {'addr': 969508, 'reg': 'x4'},
          {'addr': 970388, 'reg': 'x12'}, {'addr': 970652, 'reg': 'x6'}, {'addr': 970976, 'reg': 'x14'},
          {'addr': 971940, 'reg': 'x8'}, {'addr': 972264, 'reg': 'x3'}, {'addr': 973204, 'reg': 'x1'},
          {'addr': 973484, 'reg': 'x19'}, {'addr': 973864, 'reg': 'x14'}, {'addr': 974140, 'reg': 'x15'},
          {'addr': 975092, 'reg': 'x8'}, {'addr': 975180, 'reg': 'x6'}, {'addr': 975428, 'reg': 'x1'},
          {'addr': 976192, 'reg': 'x8'}, {'addr': 976576, 'reg': 'x6'}, {'addr': 976968, 'reg': 'x11'},
          {'addr': 977240, 'reg': 'x12'}, {'addr': 977504, 'reg': 'x9'}, {'addr': 977916, 'reg': 'x17'},
          {'addr': 978188, 'reg': 'x6'}, {'addr': 978284, 'reg': 'x30'}, {'addr': 978452, 'reg': 'x30'},
          {'addr': 978644, 'reg': 'x30'}, {'addr': 979008, 'reg': 'x16'}, {'addr': 979100, 'reg': 'x30'},
          {'addr': 979644, 'reg': 'x6'}, {'addr': 979972, 'reg': 'x8'}, {'addr': 981684, 'reg': 'x8'},
          {'addr': 981984, 'reg': 'x15'}, {'addr': 982508, 'reg': 'x5'}, {'addr': 982808, 'reg': 'x12'},
          {'addr': 983408, 'reg': 'x6'}, {'addr': 983700, 'reg': 'x9'}, {'addr': 983796, 'reg': 'x30'},
          {'addr': 984076, 'reg': 'x8'}, {'addr': 984916, 'reg': 'x0'}, {'addr': 985360, 'reg': 'x15'},
          {'addr': 985660, 'reg': 'x13'}, {'addr': 985988, 'reg': 'x11'}, {'addr': 986232, 'reg': 'x6'},
          {'addr': 986528, 'reg': 'x0'}, {'addr': 986876, 'reg': 'x1'}, {'addr': 987164, 'reg': 'x2'},
          {'addr': 988064, 'reg': 'x8'}, {'addr': 988380, 'reg': 'x10'}, {'addr': 989596, 'reg': 'x8'},
          {'addr': 989636, 'reg': 'x6'}, {'addr': 993032, 'reg': 'x19'}, {'addr': 993272, 'reg': 'x17'},
          {'addr': 993444, 'reg': 'x6'}, {'addr': 994444, 'reg': 'x6'}, {'addr': 994476, 'reg': 'x6'},
          {'addr': 994744, 'reg': 'x14'}, {'addr': 995748, 'reg': 'x3'}, {'addr': 996000, 'reg': 'x7'},
          {'addr': 996296, 'reg': 'x8'}, {'addr': 996964, 'reg': 'x8'}, {'addr': 997280, 'reg': 'x4'},
          {'addr': 997672, 'reg': 'x8'}, {'addr': 997920, 'reg': 'x0'}, {'addr': 998012, 'reg': 'x30'},
          {'addr': 998384, 'reg': 'x10'}, {'addr': 998696, 'reg': 'x8'}, {'addr': 998976, 'reg': 'x9'},
          {'addr': 999972, 'reg': 'x30'}, {'addr': 1000276, 'reg': 'x11'}, {'addr': 1001160, 'reg': 'x8'},
          {'addr': 1001456, 'reg': 'x14'}, {'addr': 1002824, 'reg': 'x14'}, {'addr': 1003096, 'reg': 'x7'},
          {'addr': 1003364, 'reg': 'x15'}, {'addr': 1003736, 'reg': 'x19'}, {'addr': 1004704, 'reg': 'x8'},
          {'addr': 1005156, 'reg': 'x6'}, {'addr': 1006040, 'reg': 'x8'}, {'addr': 1006096, 'reg': 'x6'},
          {'addr': 1006396, 'reg': 'x11'}, {'addr': 1006876, 'reg': 'x5'}, {'addr': 1007192, 'reg': 'x12'},
          {'addr': 1007560, 'reg': 'x19'}, {'addr': 1007820, 'reg': 'x3'}, {'addr': 1008212, 'reg': 'x17'},
          {'addr': 1009120, 'reg': 'x12'}, {'addr': 1009444, 'reg': 'x14'}, {'addr': 1009840, 'reg': 'x15'},
          {'addr': 1010108, 'reg': 'x11'}, {'addr': 1011544, 'reg': 'x8'}, {'addr': 1012604, 'reg': 'x1'},
          {'addr': 1012884, 'reg': 'x19'}, {'addr': 1013720, 'reg': 'x8'}, {'addr': 1013820, 'reg': 'x30'},
          {'addr': 1014676, 'reg': 'x8'}, {'addr': 1016200, 'reg': 'x6'}, {'addr': 1016492, 'reg': 'x9'},
          {'addr': 1016604, 'reg': 'x30'}, {'addr': 1016700, 'reg': 'x30'}, {'addr': 1016752, 'reg': 'x6'},
          {'addr': 1017016, 'reg': 'x2'}, {'addr': 1017188, 'reg': 'x30'}, {'addr': 1017536, 'reg': 'x13'},
          {'addr': 1017928, 'reg': 'x14'}, {'addr': 1018332, 'reg': 'x6'}, {'addr': 1018436, 'reg': 'x30'},
          {'addr': 1018824, 'reg': 'x0'}, {'addr': 1019092, 'reg': 'x3'}, {'addr': 1019348, 'reg': 'x14'},
          {'addr': 1021172, 'reg': 'x8'}, {'addr': 1022132, 'reg': 'x1'}, {'addr': 1022476, 'reg': 'x9'},
          {'addr': 1023608, 'reg': 'x11'}, {'addr': 1024568, 'reg': 'x12'}, {'addr': 1024800, 'reg': 'x6'},
          {'addr': 1025724, 'reg': 'x13'}, {'addr': 1026108, 'reg': 'x15'}, {'addr': 1026988, 'reg': 'x8'},
          {'addr': 1027328, 'reg': 'x2'}, {'addr': 1027608, 'reg': 'x2'}, {'addr': 1027940, 'reg': 'x1'},
          {'addr': 1028580, 'reg': 'x15'}, {'addr': 1028888, 'reg': 'x19'}, {'addr': 1029236, 'reg': 'x3'},
          {'addr': 1030244, 'reg': 'x10'}, {'addr': 1030684, 'reg': 'x4'}, {'addr': 1031768, 'reg': 'x8'},
          {'addr': 1032884, 'reg': 'x8'}, {'addr': 1033192, 'reg': 'x2'}, {'addr': 1034420, 'reg': 'x0'},
          {'addr': 1034732, 'reg': 'x16'}, {'addr': 1035044, 'reg': 'x11'}, {'addr': 1035356, 'reg': 'x2'},
          {'addr': 1035632, 'reg': 'x11'}, {'addr': 1036176, 'reg': 'x6'}, {'addr': 1036768, 'reg': 'x9'},
          {'addr': 1037040, 'reg': 'x2'}, {'addr': 1037860, 'reg': 'x1'}, {'addr': 1038132, 'reg': 'x0'},
          {'addr': 1038724, 'reg': 'x9'}, {'addr': 1039044, 'reg': 'x19'}, {'addr': 1040268, 'reg': 'x9'},
          {'addr': 1040548, 'reg': 'x16'}, {'addr': 1040832, 'reg': 'x14'}, {'addr': 1041664, 'reg': 'x8'},
          {'addr': 1042004, 'reg': 'x10'}, {'addr': 1042276, 'reg': 'x4'}, {'addr': 1042372, 'reg': 'x30'},
          {'addr': 1043368, 'reg': 'x8'}, {'addr': 1043620, 'reg': 'x10'}, {'addr': 1043904, 'reg': 'x14'},
          {'addr': 1044940, 'reg': 'x8'}, {'addr': 1046080, 'reg': 'x8'}, {'addr': 1046524, 'reg': 'x11'},
          {'addr': 1047312, 'reg': 'x8'}, {'addr': 1048252, 'reg': 'x8'}, {'addr': 1048528, 'reg': 'x1'},
          {'addr': 1048804, 'reg': 'x17'}, {'addr': 1049804, 'reg': 'x5'}, {'addr': 1049908, 'reg': 'x30'},
          {'addr': 1050224, 'reg': 'x3'}, {'addr': 1051416, 'reg': 'x17'}, {'addr': 1052184, 'reg': 'x8'},
          {'addr': 1052460, 'reg': 'x7'}, {'addr': 1053488, 'reg': 'x12'}, {'addr': 1054188, 'reg': 'x8'},
          {'addr': 1055012, 'reg': 'x8'}, {'addr': 1055340, 'reg': 'x2'}, {'addr': 1056148, 'reg': 'x30'},
          {'addr': 1056448, 'reg': 'x17'}, {'addr': 1056828, 'reg': 'x11'}, {'addr': 1057628, 'reg': 'x8'},
          {'addr': 1057900, 'reg': 'x9'}, {'addr': 1057952, 'reg': 'x6'}, {'addr': 1058208, 'reg': 'x19'},
          {'addr': 1058548, 'reg': 'x4'}, {'addr': 1059356, 'reg': 'x8'}, {'addr': 1059464, 'reg': 'x6'},
          {'addr': 1060312, 'reg': 'x8'}, {'addr': 1061104, 'reg': 'x6'}, {'addr': 1063116, 'reg': 'x4'},
          {'addr': 1063460, 'reg': 'x6'}, {'addr': 1065120, 'reg': 'x7'}, {'addr': 1065908, 'reg': 'x8'},
          {'addr': 1067860, 'reg': 'x8'}, {'addr': 1069400, 'reg': 'x10'}, {'addr': 1069660, 'reg': 'x6'},
          {'addr': 1070476, 'reg': 'x8'}, {'addr': 1070756, 'reg': 'x16'}, {'addr': 1071176, 'reg': 'x6'},
          {'addr': 1071472, 'reg': 'x13'}, {'addr': 1071820, 'reg': 'x8'}, {'addr': 1072180, 'reg': 'x0'},
          {'addr': 1073384, 'reg': 'x4'}, {'addr': 1073636, 'reg': 'x9'}, {'addr': 1073736, 'reg': 'x6'},
          {'addr': 1074020, 'reg': 'x8'}, {'addr': 1074300, 'reg': 'x13'}, {'addr': 1074352, 'reg': 'x6'},
          {'addr': 1075952, 'reg': 'x9'}, {'addr': 1076240, 'reg': 'x16'}, {'addr': 1077308, 'reg': 'x6'},
          {'addr': 1077696, 'reg': 'x0'}]

# brlist.append(
#     {
#         "addr": 0x01AC168 + base,
#         "reg": "x1",
#     }
# )

print("br", brlist)


def trace_hook(state):
    pc = state.solver.eval(state.regs.pc) - base
    code = state.memory.load(pc, 4)
    code_bytes = state.solver.eval(code, cast_to=bytes)
    for instr in disasm.disasm(code_bytes, pc):
        print(f"PC: 0x{pc:x} | {instr.mnemonic} {instr.op_str}")

    # print_reg(state)


def evlBr(addr, reg):
    print("evlBr", "addr", hex(addr), "reg", reg)
    start = max(text_start, addr - 0x300)
    if start < text_start:
        start = text_start
    state = project.factory.blank_state(addr=start)
    state.options.add(angr.options.CALLLESS)  # Avoid external calls
    sim = project.factory.simgr(state)
    lastPc = start
    # Step until target address, limit path explosion
    while lastPc <= addr:
        sim.step(num_inst=1)

        if not len(sim.active) == 1:
            print("---end---", hex(lastPc + 4))
            state = project.factory.blank_state(addr=lastPc + 4)
            sim = project.factory.simgr(state)
            sim.step(num_inst=1)
            lastPc += 4
            continue

        for active_state in sim.active[:]:
            pc = active_state.solver.eval(active_state.regs.pc)
            if pc < lastPc or pc > addr:
                print("---end2---", hex(lastPc + 4))
                state = project.factory.blank_state(addr=lastPc + 4)
                sim = project.factory.simgr(state)
                sim.step(num_inst=1)
                lastPc += 4
                break

            lastPc = pc
            if pc == addr:
                try:
                    reg_value = active_state.regs.get(reg)
                    if active_state.solver.symbolic(reg_value):
                        print(f"寄存器 {reg} 的值是符号化的")
                        continue
                    concrete_value = active_state.solver.eval(reg_value, cast_to=int)
                    print(f"寄存器 {reg} 在 0x{addr:x} 的值: 0x{concrete_value:x}")
                    return concrete_value
                except Exception as e:
                    print(f"无法获取寄存器 {reg} 的值: {e}")

    print(f"未找到到达 0x{addr:x} 的有效状态")
    return None


for item in brlist:
    try:
        item["real"] = evlBr(item["addr"], item["reg"])
    except Exception as e:
        print(e)
print(brlist)
# def trace_register_value(project, target_addr, register_name):
#     target_block = project.factory.block(0x016E900 + base)
#
#     observation_points = [(target_addr, None, OP_BEFORE)]
#
#     rda = project.analyses.ReachingDefinitions(
#         subject=target_block,
#         observation_points=observation_points,
#         track_tmps=True,
#         track_consts=True
#     )
#
#     register_offset = project.arch.registers[register_name][0]
#
#     results = []
#     for defn in rda.all_definitions:
#         if defn.offset == register_offset:
#             code_loc = defn.codeloc
#
#             try:
#                 block = project.factory.block(code_loc.ins_addr)
#                 instr = block.capstone.insns[0]
#                 asm = f"{instr.mnemonic} {instr.op_str}"
#             except Exception:
#                 asm = "Unknown instruction"
#
#             # 提取符号表达式
#             value_expr = defn.data.ast if hasattr(defn.data, 'ast') else defn.data
#
#             results.append({
#                 'address': hex(code_loc.ins_addr),
#                 'instruction': asm,
#                 'value': value_expr
#             })
#
#     return results
#
#
# # 使用示例
#
# target_address = base + 0x16E920
# register = "x6"
#
# analysis_result = trace_register_value(project, target_address, register)
#
# # 打印结果
# print(f"寄存器 {register} 在地址 {hex(target_address)} 处的值来源：")
# for item in analysis_result:
#     print(f"指令地址：{item['address']}")
#     print(f"指令内容：{item['instruction']}")
#     print(f"值表达式：{item['value']}\n")

package main

import "base:intrinsics"
import "core:fmt"
import "core:os"

RegisterCode :: enum {
    al = 0b0000,
    ax = 0b0001,
    cl = 0b0010,
    cx = 0b0011,
    dl = 0b0100,
    dx = 0b0101,
    bl = 0b0110,
    bx = 0b0111,
    ah = 0b1000,
    sp = 0b1001,
    ch = 0b1010,
    bp = 0b1011,
    dh = 0b1100,
    si = 0b1101,
    bh = 0b1110,
    di = 0b1111,
}

Opcode :: enum {
    NOTHING,
    MOV,
    ADD,
    SUB,
    CMP,
    JNZ,
    JE,
    JL,
    JLE,
    JB,
    JBE,
    JP,
    JO,
    JS,
    JNL,
    JG,
    JNB,
    JA,
    JNP,
    JNO,
    JNS,
    LOOP,
    LOOPZ,
    LOOPNZ,
    JCXZ,
}

Memory :: struct {
    base:         RegisterCode,
    pointer:      RegisterCode,
    displacement: union {
        i8,
        i16,
    },
}

Data :: union {
    i8,
    i16,
}

Immediate :: union {
    i8,
    i16,
}

Location :: union {
    RegisterCode,
    Memory,
    Immediate,
}

Instruction :: struct {
    op:   Opcode,
    dest: Location,
    src:  Location,
    data: i8,
}

Registers :: struct {
    ax: u16,
    bx: u16,
    cx: u16,
    dx: u16,
    si: u16,
    di: u16,
    sp: u16,
    bp: u16,
}

Flags :: struct {
    zero: bool,
    sign: bool,
}


print_location :: proc(loc: Location) -> string {
    switch v in loc {
    case Memory:
        {
            // [a + b + 12]
            if v.base != nil && v.pointer != nil {
                switch d in v.displacement {
                case i8:
                    if d == 0 {
                        return fmt.tprintf("[%v + %v]", v.base, v.pointer)
                    }
                    return fmt.tprintf("[%v + %v + %d]", v.base, v.pointer, v.displacement)
                case i16:
                    if d == 0 {
                        return fmt.tprintf("[%v + %v]", v.base, v.pointer)
                    }
                    return fmt.tprintf("[%v + %v + %d]", v.base, v.pointer, v.displacement)
                case nil:
                    return fmt.tprintf("[%v + %v]", v.base, v.pointer)
                }
            }

            // [a + 12]
            if v.base != nil && v.pointer == nil {
                switch d in v.displacement {
                case i8:
                    if d == 0 {
                        return fmt.tprintf("[%v]", v.base)
                    }
                    return fmt.tprintf("[%v + %d]", v.base, v.displacement)
                case i16:
                    if d == 0 {
                        return fmt.tprintf("[%v]", v.base)
                    }
                    return fmt.tprintf("[%v + %d]", v.base, v.displacement)
                case nil:
                    return fmt.tprintf("[%v]", v.base)
                }
            }
            if v.base == nil && v.pointer == nil {
                // direct access
                return fmt.tprintf("[%d]", v.displacement.(i16))
            }
        }
    case RegisterCode:
        {
            return fmt.tprintf("%v", v)
        }
    case Immediate:
        switch d in v {
        case i8:
            return fmt.tprintf("%d", d)
        case i16:
            return fmt.tprintf("%d", d)
        }
    }
    return fmt.tprintf("%v", loc)
}

displace_memory :: proc(mem: ^Memory, mod: u8, data: []u8) -> int {
    if mod == 0b00 {
        return 2
    } else if mod == 0b01 {
        mem.displacement = i8(data[2])
        return 3
    } else if mod == 0b10 {
        mem.displacement = i16(data[3]) << 8 + i16(data[2])
        return 4
    }
    return 0
}

estimate_ea :: proc(mem: Memory) -> int {
    estimate := 0

    // Table manual page 66
    if mem.base == nil && mem.pointer == nil && mem.displacement != nil {
        estimate += 6
    } else if mem.displacement == nil && mem.base != nil && mem.pointer == nil {
        estimate += 5
    } else if mem.displacement == nil && mem.base == nil && mem.pointer != nil {
        estimate += 5
    } else if mem.displacement != nil && mem.base != nil && mem.pointer == nil {
        estimate += 9
    } else if mem.displacement != nil && mem.base == nil && mem.pointer != nil {
        estimate += 9
    } else if mem.displacement == nil && mem.base != nil && mem.pointer != nil {
        if mem.base == .bp && mem.pointer == .di {
            estimate += 7
        } else if mem.base == .bx && mem.pointer == .si {
            estimate += 7
        } else if mem.base == .bp && mem.pointer == .si {
            estimate += 8
        } else if mem.base == .bx && mem.pointer == .di {
            estimate += 8
        }
    } else if mem.displacement != nil && mem.base != nil && mem.pointer != nil {
        if mem.base == .bp && mem.pointer == .di {
            estimate += 11
        } else if mem.base == .bx && mem.pointer == .si {
            estimate += 11
        } else if mem.base == .bp && mem.pointer == .si {
            estimate += 12
        } else if mem.base == .bx && mem.pointer == .di {
            estimate += 12
        }
    }

    return estimate
}

main :: proc() {
    file: string
    estimation := false
    if len(os.args) == 3 {
        if os.args[1] == "estimate" {
            file = os.args[2]
            estimation = true
        }
    } else {
        file = os.args[1]
    }

    data, ok := os.read_entire_file(file)

    if !ok {
        fmt.eprintln("Error: can't read file")
        return
    }

    registers: Registers
    flags: Flags
    ip: int
    memory: []u16 = make([]u16, 1024 * 1024 / 2)

    estimate_sum := 0

    // copy the program in the memory
    intrinsics.mem_copy(rawptr(&memory[0]), rawptr(&data[0]), len(data))

    for {
        if ip >= len(data) {break}

        ins, ins_len := decode_instruction(data[ip:])
        ip += ins_len

        // estimate instruction cycles
        if estimation {
            estimate := 0
            ea := 0
            instructions: [dynamic]Instruction

            i := 0
            for i < len(data) {
                ins, n := decode_instruction(data[i:])
                i += n
                append(&instructions, ins)
            }


            #partial switch ins.op {
            case .ADD:
                #partial switch dest in ins.dest {
                case RegisterCode:
                    switch src in ins.src {
                    case RegisterCode:
                        estimate += 3
                    case Immediate:
                        estimate += 4
                    case Memory:
                        estimate += 9
                        ea += estimate_ea(src)
                        estimate += ea
                    }
                case Memory:
                    ea += estimate_ea(dest)
                    estimate += ea

                    switch src in ins.src {
                    case RegisterCode:
                        estimate += 16
                    case Immediate:
                        estimate += 17
                    case Memory:
                        panic("add mem, mem not possible")
                    }
                case Immediate:
                    panic("add imm, x not possible")
                }
            case .MOV:
                #partial switch dest in ins.dest {
                case RegisterCode:
                    switch src in ins.src {
                    case RegisterCode:
                        estimate += 2
                    case Immediate:
                        estimate += 4
                    case Memory:
                        estimate += 8
                        ea += estimate_ea(src)
                        estimate += ea
                    }
                case Memory:
                    ea += estimate_ea(dest)

                    switch src in ins.src {
                    case RegisterCode:
                        if src == .ax {
                            estimate += 10
                        } else {
                            estimate += 8 + ea
                        }
                    case Immediate:
                        estimate += 10 + ea
                    case Memory:
                        panic("add mem, mem not possible")
                    }
                case Immediate:
                    panic("add imm, x not possible")
                }

            }
            estimate_sum += estimate
            fmt.println(
                ins.op,
                print_location(ins.dest),
                print_location(ins.src),
                ";",
                estimate,
                "ea:",
                ea,
                "/",
                estimate_sum,
            )
        }

        #partial switch ins.op {
        case .MOV:
            {
                dest: ^u16
                switch destCode in ins.dest {
                case RegisterCode:
                    dest = get_register(&registers, destCode)
                case Immediate:
                    panic("Not possible to write in an immediate")
                case Memory:
                    addr: u16 = 0

                    if destCode.base != nil {
                        addr += get_register(&registers, destCode.base)^
                    }
                    if destCode.pointer != nil {
                        addr += get_register(&registers, destCode.pointer)^
                    }
                    if destCode.displacement != nil {
                        #partial switch v in destCode.displacement {
                        case i8:
                            addr += u16(v)
                        case i16:
                            addr += u16(v)
                        }
                    }
                    dest = &memory[addr]
                }

                switch src in ins.src {
                case Immediate:
                    #partial switch im in src {
                    case i16:
                        dest^ = u16(im)
                    }
                case RegisterCode:
                    dest^ = get_register(&registers, src)^
                case Memory:
                    addr: u16 = 0

                    if src.base != nil {
                        addr += get_register(&registers, src.base)^
                    }
                    if src.pointer != nil {
                        addr += get_register(&registers, src.pointer)^
                    }
                    if src.displacement != nil {
                        #partial switch v in src.displacement {
                        case i8:
                            addr += u16(v)
                        case i16:
                            addr += u16(v)
                        }
                    }
                    dest^ = memory[int(u16(addr))]
                }
            }
        case .ADD:
            if code, ok := ins.dest.(RegisterCode); ok {
                reg := get_register(&registers, code)

                // mov reg, imm
                if imm, ok := ins.src.(Immediate); ok {
                    #partial switch im in imm {
                    case i16:
                        reg^ += u16(im)
                        flags.sign = reg^ & 0b1000000000000000 == 1
                        flags.zero = reg^ == 0
                    case i8:
                        reg^ += u16(im)
                        flags.sign = reg^ & 0b1000000000000000 == 1
                        flags.zero = reg^ == 0
                    }
                }

                // mov reg, reg
                if code2, ok := ins.src.(RegisterCode); ok {
                    reg^ += get_register(&registers, code2)^
                    flags.sign = reg^ & 0b1000000000000000 > 0
                    flags.zero = reg^ == 0
                }
            }
        case .SUB:
            if code, ok := ins.dest.(RegisterCode); ok {
                reg := get_register(&registers, code)

                // mov reg, imm
                if imm, ok := ins.src.(Immediate); ok {
                    #partial switch im in imm {
                    case i16:
                        reg^ -= u16(im)
                        flags.sign = reg^ & 0b1000000000000000 == 1
                        flags.zero = reg^ == 0
                    case i8:
                        reg^ -= u16(im)
                        flags.sign = reg^ & 0b1000000000000000 == 1
                        flags.zero = reg^ == 0
                    }
                }

                // mov reg, reg
                if code2, ok := ins.src.(RegisterCode); ok {
                    reg^ -= get_register(&registers, code2)^
                    flags.sign = reg^ & 0b1000000000000000 > 0
                    flags.zero = reg^ == 0
                }
            }
        case .CMP:
            if code, ok := ins.dest.(RegisterCode); ok {
                reg := get_register(&registers, code)

                // mov reg, imm
                if imm, ok := ins.src.(Immediate); ok {
                    #partial switch im in imm {
                    case i8:
                        tmp: u16 = reg^ - u16(im)
                        flags.sign = tmp & 0b1000000000000000 == 1
                        flags.zero = tmp == 0
                    case i16:
                        tmp: u16 = reg^ - u16(im)
                        flags.sign = tmp & 0b1000000000000000 == 1
                        flags.zero = tmp == 0
                    }
                }

                // mov reg, reg
                if code2, ok := ins.src.(RegisterCode); ok {
                    tmp: u16 = reg^ - get_register(&registers, code2)^
                    flags.sign = tmp & 0b1000000000000000 > 0
                    flags.zero = tmp == 0
                }
            }
        case .JNZ:
            if !flags.zero {
                ip += int(ins.data)
            }
        case:
            panic("unknown instruction")
        }
    }

    fmt.println("\nResult:")
    fmt.printf("AX %x\n", registers.ax)
    fmt.printf("BX %x\n", registers.bx)
    fmt.printf("CX %x\n", registers.cx)
    fmt.printf("DX %x\n", registers.dx)
    fmt.printf("SP %x\n", registers.sp)
    fmt.printf("BP %x\n", registers.bp)
    fmt.printf("SI %x\n", registers.si)
    fmt.printf("DI %x\n", registers.di)
    fmt.printf("\nIP %x\n", ip)
    if estimation {
        fmt.println("\nEstimated cycles:", estimate_sum)
    }

}

get_register :: proc(registers: ^Registers, code: RegisterCode) -> ^u16 {
    #partial switch code {
    case .ax:
        return &registers.ax
    case .bx:
        return &registers.bx
    case .cx:
        return &registers.cx
    case .dx:
        return &registers.dx
    case .sp:
        return &registers.sp
    case .bp:
        return &registers.bp
    case .si:
        return &registers.si
    case .di:
        return &registers.di
    case:
        panic("unknown register")
    }
}

decode_instruction :: proc(data: []u8) -> (Instruction, int) {
    source: Location
    destination: Location

    i := 0

    // mov reg, reg / reg, mem / mem, reg / mem, mem
    {
        opcode: Opcode = nil
        switch data[i] & 0b11111100 {
        case 0b10001000:
            opcode = .MOV
        case 0b00000000:
            opcode = .ADD
        case 0b00101000:
            opcode = .SUB
        case 0b00111000:
            opcode = .CMP
        }

        if opcode != nil {
            dest, src, n := get_operands(data[i:])
            destination = dest
            source = src
            i += n
            return Instruction{opcode, destination, source, 0}, i
        }
    }

    // mov reg, imm
    if data[i] & 0b11110000 == 0b10110000 {
        w := (data[i] & 0b00001000) >> 3
        reg := (data[i] & 0b00000111)

        dest := RegisterCode((reg << 1) + w)
        if w == 1 {
            // 16 bit
            ins := Instruction{.MOV, dest, Immediate(i16(data[i + 2]) << 8 + i16(data[i + 1])), 0}
            i += 3
            return ins, i
        } else {
            // 8 bit
            ins := Instruction{.MOV, dest, Immediate(i8(data[i + 1])), 0}
            i += 2
            return ins, i
        }
    }
    // mov mem, imm/ mov reg, imm
    if data[i] & 0b11111110 == 0b11000110 {
        w := (data[i] & 0b00000001)
        mod := (data[i + 1] & 0b11000000) >> 6
        rm := (data[i + 1] & 0b00000111)

        if mod == 0b00 {
            dest, n := get_operand(data[i:], mod, rm, 0, w)
            i += n
            src: Immediate = i16(data[i + 1] << 8) + i16(data[i])
            i += 2
            return Instruction{.MOV, dest, src, 0}, i
            // memory mode no displacement
        } else if mod == 0b01 {
            // 8bit
            if w == 1 {
                dest, n := get_operand(data[i:], mod, rm, 0, w)
                i += n
                src: Immediate = i16(data[i + 1] << 8) + i16(data[i])
                i += 2
                return Instruction{.MOV, dest, src, 0}, i
            } else {
                dest, n := get_operand(data[i:], mod, rm, 0, w)
                i += n
                src: Immediate = i16(data[i])
                i += 1
                return Instruction{.MOV, dest, src, 0}, i
            }
        } else if mod == 0b10 {
            // 16Bit
            dest, n := get_operand(data[i:], mod, rm, 0, w)
            i += n
            src: Immediate = i16(data[i + 1] << 8) + i16(data[i])
            i += 2
            return Instruction{.MOV, dest, src, 0}, i
        }
    }

    // add reg, imm / mem, imm
    if data[i] & 0b11111100 == 0b10000000 {
        s := (data[i] & 0b00000010) >> 1
        w := (data[i] & 0b00000001)

        mod := (data[i + 1] & 0b11000000) >> 6
        op := (data[i + 1] & 0b00111000) >> 3
        rm := (data[i + 1] & 0b00000111)

        operation: string
        opcode: Opcode
        switch op {
        case 0b000:
            operation = "add"
            opcode = .ADD
        case 0b101:
            operation = "sub"
            opcode = .SUB
        case 0b111:
            operation = "cmp"
            opcode = .CMP
        }

        dest, n := get_operand(data[i:], mod, rm, s, w)
        i += n
        src: Immediate

        // immediate
        if w == 1 && s == 0 {
            src = i16(data[i + 1]) << 8 + i16(data[i])
            i += 2
        } else {
            src = i8(data[i])
            i += 1
        }

        if w == 1 && s == 0 {
            prefix := ""
            if _, ok := dest.(Memory); ok {
                prefix = "word "
            }
            return Instruction{opcode, dest, src, 0}, i
        } else {
            prefix := ""
            if _, ok := dest.(Memory); ok {
                if w == 1 {
                    prefix = "word "
                } else {
                    prefix = "byte "
                }
            }
            return Instruction{opcode, dest, src, 0}, i
        }
    }

    // add acc, imm
    if data[i] & 0b11111110 == 0b00000100 {
        dest: Location
        src: Immediate
        w := (data[i] & 0b00000001)

        i += 1
        if w == 1 {
            dest = RegisterCode.ax
            src = i16(data[i + 1]) << 8 + i16(data[i])
            i += 2
        } else {
            dest = RegisterCode.al
            src = i16(data[i])
            i += 1
        }
        return Instruction{.ADD, dest, src, 0}, i
    }

    // sub acc, imm
    if data[i] & 0b11111110 == 0b00101100 {
        dest: Location
        src: Immediate
        w := (data[i] & 0b00000001)

        i += 1
        if w == 1 {
            dest = RegisterCode.ax
            src = i16(data[i + 1]) << 8 + i16(data[i])
            i += 2
        } else {
            dest = RegisterCode.al
            src = i16(data[i])
            i += 1
        }
        return Instruction{.SUB, dest, src, 0}, i
    }

    // cmp acc, imm
    if data[i] & 0b11111110 == 0b00111100 {
        dest: Location
        src: Immediate
        w := (data[i] & 0b00000001)

        i += 1
        if w == 1 {
            dest = RegisterCode.ax
            src = i16(data[i + 1]) << 8 + i16(data[i])
            i += 2
        } else {
            dest = RegisterCode.al
            src = i16(data[i])
            i += 1
        }
        return Instruction{.CMP, dest, src, 0}, i
    }

    /// jumps
    {
        opcode: Opcode = nil

        switch data[i] {
        case 0b01110101:
            opcode = .JNZ
        case 0b01110100:
            opcode = .JE
        case 0b01111100:
            opcode = .JL
        case 0b01111110:
            opcode = .JLE
        case 0b01110010:
            opcode = .JB
        case 0b01110110:
            opcode = .JBE
        case 0b01111010:
            opcode = .JP
        case 0b01110000:
            opcode = .JO
        case 0b01111000:
            opcode = .JS
        case 0b01111101:
            opcode = .JNL
        case 0b01111111:
            opcode = .JG
        case 0b01110011:
            opcode = .JNB
        case 0b01110111:
            opcode = .JA
        case 0b01111011:
            opcode = .JNP
        case 0b01110001:
            opcode = .JNO
        case 0b01111001:
            opcode = .JNS
        case 0b11100010:
            opcode = .LOOP
        case 0b11100001:
            opcode = .LOOPZ
        case 0b11100000:
            opcode = .LOOPNZ
        case 0b11100011:
            opcode = .JCXZ
        }

        i += 1
        if opcode != nil {
            offset := data[i]
            offset += 0
            i += 1
            return Instruction{opcode, nil, nil, i8(offset)}, i
        }
    }

    panic("should not happen")
}

get_operand :: proc(data: []u8, mod, rm: u8, s, w: u8) -> (Location, int) {
    source: Location

    // reg, reg
    if mod == 0b11 {
        return RegisterCode((rm << 1) + w), 2
    }

    // reg, mem / mem, reg
    i := 0
    src: Memory

    switch rm {
    case 0b000:
        src = Memory{.bx, .si, nil}
    case 0b001:
        src = Memory{.bx, .di, nil}
    case 0b010:
        src = Memory{.bp, .si, nil}
    case 0b011:
        src = Memory{.bp, .di, nil}
    case 0b100:
        src = Memory{.si, nil, nil}
    case 0b101:
        src = Memory{.di, nil, nil}
    case 0b111:
        src = Memory{.bx, nil, nil}
    case 0b110:
        if mod == 0b00 {
            // direct address
            disp: u16 = u16(data[i + 3]) << 8 + u16(data[i + 2])
            src = Memory{nil, nil, i16(disp)}

        } else if mod == 0b01 {
            src = Memory{.bp, nil, nil}
        } else if mod == 0b10 {
            src = Memory{.bp, nil, nil}
        }
    }

    if rm == 0b110 && mod == 0b00 {
        // direct access
        i += 4
        displace_memory(&src, 0b10, data)
    } else {
        i += displace_memory(&src, mod, data)
    }
    source = src

    return source, i
}

get_operands :: proc(data: []u8) -> (Location, Location, int) {
    destination: Location
    source: Location

    d := (data[0] & 0b00000010) >> 1
    w := (data[0] & 0b00000001)

    mod := (data[1] & 0b11000000) >> 6
    reg := (data[1] & 0b00111000) >> 3
    rm := (data[1] & 0b00000111)

    // number of bytes consumed
    i := 0

    // reg, reg
    if mod == 0b11 {
        destination = RegisterCode((rm << 1) + w)
        source = RegisterCode((reg << 1) + w)
        i += 2
        return destination, source, i
    }

    // reg, mem / mem, reg
    destination = RegisterCode((reg << 1) + w)
    src: Memory

    switch rm {
    case 0b000:
        src = Memory{.bx, .si, nil}
    case 0b001:
        src = Memory{.bx, .di, nil}
    case 0b010:
        src = Memory{.bp, .si, nil}
    case 0b011:
        src = Memory{.bp, .di, nil}
    case 0b100:
        src = Memory{.si, nil, nil}
    case 0b101:
        src = Memory{.di, nil, nil}
    case 0b111:
        src = Memory{.bx, nil, nil}
    case 0b110:
        if mod == 0b00 {
            // direct access
            disp: u16 = u16(data[i + 3]) << 8 + u16(data[i + 2])
            src = Memory{nil, nil, i16(disp)}
        } else if mod == 0b01 {
            src = Memory{.bp, nil, nil}
        } else if mod == 0b10 {
            src = Memory{.bp, nil, nil}
        }
    }

    if rm == 0b110 && mod == 0b00 {
        // direct access
        i += 4
    } else {
        i += displace_memory(&src, mod, data)
    }
    source = src

    // flip src/dest
    if d == 0 {
        tmp := source
        source = destination
        destination = tmp
    }

    return destination, source, i
}

flip :: proc(a, b: Location, d: u8) -> (Location, Location) {
    if d == 0 {
        return b, a
    }
    return a, b
}

SECTIONS {
  . = 0x02100000;
  .text : { *(.text*) *(.rodata*) }
}

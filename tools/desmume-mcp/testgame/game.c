/*
 * Tiny bare-metal NDS test game (ARM9 only, no libnds) used to exercise the
 * debugging tools. It deliberately mirrors the structure of a real game:
 *
 *  - a player struct in RAM that reacts to input (move with the d-pad, A to
 *    take damage) and is drawn into a 2D framebuffer on the top screen;
 *  - a level file loaded from the cartridge through a small file system
 *    reader (fs_read_file -> card_read_block), at boot and when START is
 *    pressed;
 *  - a 2D tilemap (from the level file) that build_display_list() turns into
 *    3D quads in a RAM display list, which is DMA'd to the geometry engine
 *    through the GX FIFO every frame, followed by SWAP_BUFFERS.
 *
 * The symbols are in testgame.sym (ground truth for the tests).
 */
typedef unsigned char u8; typedef unsigned short u16; typedef unsigned int u32; typedef int s32;
typedef volatile u8 vu8; typedef volatile u16 vu16; typedef volatile u32 vu32;

#define REG_DISPCNT    (*(vu32*)0x04000000)
#define REG_VCOUNT     (*(vu16*)0x04000006)
#define REG_DMA0SAD    (*(vu32*)0x040000B0)
#define REG_DMA0DAD    (*(vu32*)0x040000B4)
#define REG_DMA0CNT    (*(vu32*)0x040000B8)
#define REG_KEYINPUT   (*(vu16*)0x04000130)
#define REG_AUXSPICNT  (*(vu16*)0x040001A0)
#define REG_ROMCTRL    (*(vu32*)0x040001A4)
#define REG_CARDCMD    ((vu8*)0x040001A8)
#define REG_EXMEMCNT   (*(vu16*)0x04000204)
#define REG_VRAMCNT_A  (*(vu8*)0x04000240)
#define REG_POWCNT1    (*(vu32*)0x04000304)
#define REG_GXFIFO     (*(vu32*)0x04000400)
#define REG_SWAP_BUFFERS (*(vu32*)0x04000540)
#define REG_CARD_DATA  (*(vu32*)0x04100010)
#define FB             ((vu16*)0x06800000)
#define RGB(r,g,b)     (0x8000 | (r) | ((g)<<5) | ((b)<<10))

#define FILE_LEVEL1    4       /* data/level1.map, see mkrom.py */
#define MAP_W          4
#define MAP_H          4

struct player { int x, y; int hp; int max_hp; int score; u32 frames; };
struct player g_player = { 100, 80, 50, 50, 0, 0 };
volatile u32 g_last_keys;

u8  g_tilemap[MAP_H][MAP_W];              /* the level's 2D tilemap */
u32 g_display_list[512];                  /* geometry commands built from the tilemap */
u32 g_display_list_words;
u32 g_card_buf[128];                      /* one 0x200 byte card block */
u32 g_levels_loaded;

/* ---------------------------------------------------------------- 2D --- */

__attribute__((noinline)) void fill_rect(int x, int y, int w, int h, u16 c) {
    for (int j = y; j < y + h; j++)
        for (int i = x; i < x + w; i++)
            if (i >= 0 && i < 256 && j >= 0 && j < 192) FB[j * 256 + i] = c;
}

__attribute__((noinline, target("thumb"))) int apply_damage(struct player *p, int amount) {
    p->hp -= amount;
    if (p->hp < 0) p->hp = p->max_hp;   /* respawn */
    return p->hp;
}

/* ------------------------------------------------------- cartridge --- */

__attribute__((noinline)) void card_read_block(u32 rom_addr, u32 *dst) {
    REG_AUXSPICNT = 0x8000;                        /* enable slot 1, ROM mode */
    REG_CARDCMD[0] = 0xB7;                         /* KEY2 data read */
    REG_CARDCMD[1] = rom_addr >> 24;
    REG_CARDCMD[2] = rom_addr >> 16;
    REG_CARDCMD[3] = rom_addr >> 8;
    REG_CARDCMD[4] = rom_addr;
    REG_CARDCMD[5] = REG_CARDCMD[6] = REG_CARDCMD[7] = 0;
    REG_ROMCTRL = 0xA1000000;                      /* start, 0x200 byte block */
    u32 n = 0;
    while (REG_ROMCTRL & 0x80000000) {
        if (REG_ROMCTRL & 0x00800000) {
            u32 w = REG_CARD_DATA;
            if (n < 128) dst[n++] = w;
        }
    }
}

/* look the file up in the FAT and load it (small files only). Like real
 * games, the FAT location comes from the copy of the ROM header that the
 * BIOS leaves in RAM: retail cards refuse data reads below 0x8000. */
__attribute__((noinline)) u32 fs_read_file(u32 file_id, void *dst, u32 max_len) {
    u32 fat_off = *(vu32 *)(0x027FFE00 + 0x48);
    u32 entry = fat_off + file_id * 8;
    card_read_block(entry & ~0x1FF, g_card_buf);
    u32 start = g_card_buf[(entry & 0x1FF) / 4];
    u32 end = g_card_buf[(entry & 0x1FF) / 4 + 1];
    u32 len = end - start;
    if (len > max_len) len = max_len;
    card_read_block(start & ~0x1FF, g_card_buf);
    const u8 *src = (const u8 *)g_card_buf + (start & 0x1FF);
    for (u32 i = 0; i < len; i++) ((u8 *)dst)[i] = src[i];
    return len;
}

__attribute__((noinline)) void load_level(void) {
    fs_read_file(FILE_LEVEL1, g_tilemap, sizeof(g_tilemap));
    g_levels_loaded++;
}

/* -------------------------------------------------------------- 3D --- */

static u32 *dl_emit(u32 *p, u32 cmd, int nparams, const u32 *params) {
    *p++ = cmd;                                    /* one command per packed word */
    for (int i = 0; i < nparams; i++) *p++ = params[i];
    return p;
}

/* turn the 2D tilemap into one quad per non-empty tile */
__attribute__((noinline)) void build_display_list(void) {
    u32 *p = g_display_list;
    u32 prm[2];
    prm[0] = 0; p = dl_emit(p, 0x10, 1, prm);      /* MTX_MODE projection */
    p = dl_emit(p, 0x15, 0, prm);                  /* MTX_IDENTITY */
    prm[0] = 2; p = dl_emit(p, 0x10, 1, prm);      /* MTX_MODE position & vector */
    p = dl_emit(p, 0x15, 0, prm);                  /* MTX_IDENTITY */
    prm[0] = 1; p = dl_emit(p, 0x40, 1, prm);      /* BEGIN_VTXS quads */
    for (int ty = 0; ty < MAP_H; ty++) {
        for (int tx = 0; tx < MAP_W; tx++) {
            u32 tile = g_tilemap[ty][tx];
            if (!tile) continue;
            prm[0] = RGB(tile * 7 & 31, 31 - tile * 5 & 31, 16); p = dl_emit(p, 0x20, 1, prm); /* COLOR */
            /* 4.12 fixed point; tile (tx, ty) covers x in [tx/4-0.5, ...] */
            s32 x0 = (tx * 0x400) - 0x800, y0 = 0x800 - (ty * 0x400);
            s32 x1 = x0 + 0x3C0, y1 = y0 - 0x3C0;
            s32 corners[4][2] = { {x0, y0}, {x1, y0}, {x1, y1}, {x0, y1} };
            for (int c = 0; c < 4; c++) {
                prm[0] = (corners[c][0] & 0xFFFF) | ((u32)corners[c][1] << 16);
                prm[1] = (u32)(-0x1000) & 0xFFFF;  /* z = -1.0 */
                p = dl_emit(p, 0x23, 2, prm);      /* VTX_16 */
            }
        }
    }
    p = dl_emit(p, 0x41, 0, prm);                  /* END_VTXS */
    g_display_list_words = p - g_display_list;
}

__attribute__((noinline)) void submit_display_list(void) {
    REG_DMA0SAD = (u32)g_display_list;
    REG_DMA0DAD = (u32)&REG_GXFIFO;
    /* enable, 32 bit, GX FIFO start mode, fixed destination */
    REG_DMA0CNT = 0x80000000 | (1 << 26) | (7 << 27) | (2 << 21) | g_display_list_words;
    while (REG_DMA0CNT & 0x80000000);
    REG_SWAP_BUFFERS = 0;
}

/* ------------------------------------------------------------ game --- */

__attribute__((noinline)) void handle_input(struct player *p, u32 keys) {
    if (keys & (1 << 4)) p->x += 2;           /* right */
    if (keys & (1 << 5)) p->x -= 2;           /* left  */
    if (keys & (1 << 6)) p->y -= 2;           /* up    */
    if (keys & (1 << 7)) p->y += 2;           /* down  */
    if ((keys & 1) && !(g_last_keys & 1)) {   /* A pressed: take damage */
        apply_damage(p, 7);
        p->score += 10;
    }
    if ((keys & 8) && !(g_last_keys & 8))     /* START: reload the level */
        load_level();
    g_last_keys = keys;
}

static int old_x = -1, old_y = -1;

__attribute__((noinline)) void draw(struct player *p) {
    /* only redraw what changed; a full clear is too slow for one frame */
    if (old_x != p->x || old_y != p->y) {
        if (old_x >= 0) fill_rect(old_x, old_y, 16, 16, RGB(2, 2, 8));
        fill_rect(p->x, p->y, 16, 16, RGB(31, 31, 0));
        old_x = p->x;
        old_y = p->y;
    }
    fill_rect(8, 8, p->max_hp * 2, 6, RGB(8, 0, 0));
    fill_rect(8, 8, p->hp * 2, 6, RGB(0, 31, 0));
}

static void wait_vblank(void) {
    while (REG_VCOUNT == 192);
    while (REG_VCOUNT != 192);
}

void game_main(void) {
    REG_POWCNT1 = 0x800F;          /* LCDs, 2D engine A, 3D render + geometry */
    REG_EXMEMCNT &= ~0x0800;       /* slot 1 belongs to the ARM9 */
    REG_VRAMCNT_A = 0x80;          /* bank A enabled, LCDC */
    REG_DISPCNT = 0x00020000;      /* display mode 2: framebuffer from bank A */
    fill_rect(0, 0, 256, 192, RGB(2, 2, 8));
    load_level();
    for (;;) {
        wait_vblank();
        u32 keys = ~REG_KEYINPUT & 0x3FF;
        handle_input(&g_player, keys);
        draw(&g_player);
        build_display_list();
        submit_display_list();
        g_player.frames++;
    }
}

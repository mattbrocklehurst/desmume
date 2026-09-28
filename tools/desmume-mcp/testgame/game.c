/* tiny bare-metal NDS test game (ARM9 only, no libnds) */
typedef unsigned short u16; typedef unsigned int u32; typedef volatile u16 vu16; typedef volatile u32 vu32;
#define REG_DISPCNT   (*(vu32*)0x04000000)
#define REG_VCOUNT    (*(vu16*)0x04000006)
#define REG_KEYINPUT  (*(vu16*)0x04000130)
#define REG_POWCNT1   (*(vu32*)0x04000304)
#define VRAMCNT_A     (*(volatile unsigned char*)0x04000240)
#define FB            ((vu16*)0x06800000)
#define RGB(r,g,b)    (0x8000 | (r) | ((g)<<5) | ((b)<<10))

struct player { int x, y; int hp; int max_hp; int score; u32 frames; };
struct player g_player = { 100, 80, 50, 50, 0, 0 };
volatile u32 g_last_keys;

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

__attribute__((noinline)) void handle_input(struct player *p, u32 keys) {
    if (keys & (1 << 4)) p->x += 2;           /* right */
    if (keys & (1 << 5)) p->x -= 2;           /* left  */
    if (keys & (1 << 6)) p->y -= 2;           /* up    */
    if (keys & (1 << 7)) p->y += 2;           /* down  */
    if ((keys & 1) && !(g_last_keys & 1)) {   /* A pressed: take damage */
        apply_damage(p, 7);
        p->score += 10;
    }
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
    REG_POWCNT1 = 0x8003;
    VRAMCNT_A = 0x80;              /* bank A enabled, LCDC */
    REG_DISPCNT = 0x00020000;      /* display mode 2: framebuffer from bank A */
    fill_rect(0, 0, 256, 192, RGB(2, 2, 8));
    for (;;) {
        wait_vblank();
        u32 keys = ~REG_KEYINPUT & 0x3FF;
        handle_input(&g_player, keys);
        draw(&g_player);
        g_player.frames++;
    }
}

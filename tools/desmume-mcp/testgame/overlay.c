/* Code for overlay 0. It is stored in the ROM's overlay table but the test
 * game never loads it; it exists to exercise the ROM/overlay tooling. */
struct player { int x, y; int hp; int max_hp; int score; unsigned frames; };

int overlay_heal(struct player *p, int amount) {
    p->hp += amount;
    if (p->hp > p->max_hp) p->hp = p->max_hp;
    return p->hp;
}

/* compressible data so that the compressed overlay (id 1) actually shrinks */
const unsigned short overlay_level_table[128] = {
    1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8,
    1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8,
};

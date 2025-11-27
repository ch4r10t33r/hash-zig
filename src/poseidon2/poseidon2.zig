const std = @import("std");
const plonky3_field = @import("plonky3_field.zig");
const log = @import("../utils/log.zig");

// Plonky3-exact Poseidon2 implementation for KoalaBear field
// This implements the exact same MDS matrix and internal layer operations as Plonky3

// External round constants from Plonky3 KoalaBear (8 rounds total: 4 initial + 4 final)
pub const PLONKY3_KOALABEAR_RC16_EXTERNAL_INITIAL: [4][16]u32 = .{
    .{ 2128964168, 288780357, 316938561, 2126233899, 426817493, 1714118888, 1045008582, 1738510837, 889721787, 8866516, 681576474, 419059826, 1596305521, 1583176088, 1584387047, 1529751136 },
    .{ 1863858111, 1072044075, 517831365, 1464274176, 1138001621, 428001039, 245709561, 1641420379, 1365482496, 770454828, 693167409, 757905735, 136670447, 436275702, 525466355, 1559174242 },
    .{ 1030087950, 869864998, 322787870, 267688717, 948964561, 740478015, 679816114, 113662466, 2066544572, 1744924186, 367094720, 1380455578, 1842483872, 416711434, 1342291586, 1692058446 },
    .{ 1493348999, 1113949088, 210900530, 1071655077, 610242121, 1136339326, 2020858841, 1019840479, 678147278, 1678413261, 1361743414, 61132629, 1209546658, 64412292, 1936878279, 1980661727 },
};

pub const PLONKY3_KOALABEAR_RC16_EXTERNAL_FINAL: [4][16]u32 = .{
    .{ 1423960925, 2101391318, 1915532054, 275400051, 1168624859, 1141248885, 356546469, 1165250474, 1320543726, 932505663, 1204226364, 1452576828, 1774936729, 926808140, 1184948056, 1186493834 },
    .{ 843181003, 185193011, 452207447, 510054082, 1139268644, 630873441, 669538875, 462500858, 876500520, 1214043330, 383937013, 375087302, 636912601, 307200505, 390279673, 1999916485 },
    .{ 1518476730, 1606686591, 1410677749, 1581191572, 1004269969, 143426723, 1747283099, 1016118214, 1749423722, 66331533, 1177761275, 1581069649, 1851371119, 852520128, 1499632627, 1820847538 },
    .{ 150757557, 884787840, 619710451, 1651711087, 505263814, 212076987, 1482432120, 1458130652, 382871348, 417404007, 2066495280, 1996518884, 902934924, 582892981, 1337064375, 1199354861 },
};

// Internal round constants from Plonky3 KoalaBear (20 rounds)
pub const PLONKY3_KOALABEAR_RC16_INTERNAL: [20]u32 = .{
    2102596038, 1533193853, 1436311464, 2012303432, 839997195,  1225781098, 2011967775, 575084315,
    1309329169, 786393545,  995788880,  1702925345, 1444525226, 908073383,  1811535085, 1531002367,
    1635653662, 1585100155, 867006515,  879151050,
};

// External round constants for 24-width from Plonky3
pub const PLONKY3_KOALABEAR_RC24_EXTERNAL_INITIAL: [4][24]u32 = .{
    .{ 487143900, 1829048205, 1652578477, 646002781, 1044144830, 53279448, 1519499836, 22697702, 1768655004, 230479744, 1484895689, 705130286, 1429811285, 1695785093, 1417332623, 1115801016, 1048199020, 878062617, 738518649, 249004596, 1601837737, 24601614, 245692625, 364803730 },
    .{ 1857019234, 1906668230, 1916890890, 835590867, 557228239, 352829675, 515301498, 973918075, 954515249, 1142063750, 1795549558, 608869266, 1850421928, 2028872854, 1197543771, 1027240055, 1976813168, 963257461, 652017844, 2113212249, 213459679, 90747280, 1540619478, 324138382 },
    .{ 1377377119, 294744504, 512472871, 668081958, 907306515, 518526882, 1907091534, 1152942192, 1572881424, 720020214, 729527057, 1762035789, 86171731, 205890068, 453077400, 1201344594, 986483134, 125174298, 2050269685, 1895332113, 749706654, 40566555, 742540942, 1735551813 },
    .{ 162985276, 1943496073, 1469312688, 703013107, 1979485151, 1278193166, 548674995, 2118718736, 749596440, 1476142294, 1293606474, 918523452, 890353212, 1691895663, 1932240646, 1180911992, 86098300, 1592168978, 895077289, 724819849, 1697986774, 1608418116, 1083269213, 691256798 },
};

pub const PLONKY3_KOALABEAR_RC24_EXTERNAL_FINAL: [4][24]u32 = .{
    .{ 328586442, 1572520009, 1375479591, 322991001, 967600467, 1172861548, 1973891356, 1503625929, 1881993531, 40601941, 1155570620, 571547775, 1361622243, 1495024047, 1733254248, 964808915, 763558040, 1887228519, 994888261, 718330940, 213359415, 603124968, 1038411577, 2099454809 },
    .{ 949846777, 630926956, 1168723439, 222917504, 1527025973, 1009157017, 2029957881, 805977836, 1347511739, 540019059, 589807745, 440771316, 1530063406, 761076336, 87974206, 1412686751, 1230318064, 514464425, 1469011754, 1770970737, 1510972858, 965357206, 209398053, 778802532 },
    .{ 40567006, 1984217577, 1545851069, 879801839, 1611910970, 1215591048, 330802499, 1051639108, 321036, 511927202, 591603098, 1775897642, 115598532, 278200718, 233743176, 525096211, 1335507608, 830017835, 1380629279, 560028578, 598425701, 302162385, 567434115, 1859222575 },
    .{ 958294793, 1582225556, 1781487858, 1570246000, 1067748446, 526608119, 1666453343, 1786918381, 348203640, 1860035017, 1489902626, 1904576699, 860033965, 1954077639, 1685771567, 971513929, 1877873770, 137113380, 520695829, 806829080, 1408699405, 1613277964, 793223662, 648443918 },
};

// Internal round constants for 24-width from Plonky3
pub const PLONKY3_KOALABEAR_RC24_INTERNAL: [23]u32 = .{
    893435011,  403879071,  1363789863, 1662900517, 2043370,    2109755796, 931751726, 2091644718,
    606977583,  185050397,  946157136,  1350065230, 1625860064, 122045240,  880989921, 145137438,
    1059782436, 1477755661, 335465138,  1640704282, 1757946479, 1551204074, 681266718,
};

// KoalaBear field operations (using our Plonky3-compatible field)
const F = plonky3_field.KoalaBearField;

// S-box: x^3
pub fn sbox(x: F) F {
    return x.mul(x).mul(x);
}

// Apply MDS matrix to 4 elements (exact Plonky3 logic from apply_mat4)
// CRITICAL FIX: Rust uses .clone() to preserve original values, so we must store them first
// Matrix: [ 2 3 1 1 ]
//         [ 1 2 3 1 ]
//         [ 1 1 2 3 ]
//         [ 3 1 1 2 ]
pub fn apply_mat4(state: []F, start_idx: usize) void {
    const x = state[start_idx .. start_idx + 4];

    // Store original values (matching Rust's .clone() behavior)
    const x0 = x[0];
    const x1 = x[1];
    const x2 = x[2];
    const x3 = x[3];

    // t01 = x[0] + x[1] (using original values)
    const t01 = x0.add(x1);

    // t23 = x[2] + x[3] (using original values)
    const t23 = x2.add(x3);

    // t0123 = t01 + t23
    const t0123 = t01.add(t23);

    // t01123 = t0123 + x[1] (using original x1)
    const t01123 = t0123.add(x1);

    // t01233 = t0123 + x[3] (using original x3)
    const t01233 = t0123.add(x3);

    // The order here is important. Need to overwrite x[0] and x[2] after x[1] and x[3].
    // x[3] = t01233 + x[0].double() // 3*x[0] + x[1] + x[2] + 2*x[3] (using original x0)
    x[3] = t01233.add(x0.double());

    // x[1] = t01123 + x[2].double() // x[0] + 2*x[1] + 3*x[2] + x[3] (using original x2)
    x[1] = t01123.add(x2.double());

    // x[0] = t01123 + t01 // 2*x[0] + 3*x[1] + x[2] + x[3]
    x[0] = t01123.add(t01);

    // x[2] = t01233 + t23 // x[0] + x[1] + 2*x[2] + 3*x[3]
    x[2] = t01233.add(t23);
}

// KoalaBear internal layer parameters (exact from Plonky3)
const KOALABEAR_INTERNAL_V_16: [16]u32 = .{
    0x7f000000, // -2
    0x00000001, // 1
    0x00000002, // 2
    0x3f800000, // 1/2
    0x00000003, // 3
    0x00000004, // 4
    0xbf800000, // -1/2
    0x7fffffff, // -3
    0x7ffffffe, // -4
    0x007f0000, // 1/2^8
    0x3f000000, // 1/8
    0x0000007f, // 1/2^24
    0xff810000, // -1/2^8
    0xbf000000, // -1/8
    0xbf800000, // -1/16
    0xff00007f, // -1/2^24
};

const KOALABEAR_INTERNAL_V_24: [24]u32 = .{
    0x7f000000, // -2
    0x00000001, // 1
    0x00000002, // 2
    0x3f800000, // 1/2
    0x00000003, // 3
    0x00000004, // 4
    0xbf800000, // -1/2
    0x7fffffff, // -3
    0x7ffffffe, // -4
    0x007f0000, // 1/2^8
    0x3f000000, // 1/4
    0x3f000000, // 1/8
    0x3f800000, // 1/16
    0x3fc00000, // 1/32
    0x3fe00000, // 1/64
    0x0000007f, // 1/2^24
    0xff810000, // -1/2^8
    0xbf000000, // -1/8
    0xbf800000, // -1/16
    0xbfc00000, // -1/32
    0xbfe00000, // -1/64
    0xff000000, // -1/2^7
    0xfe000000, // -1/2^9
    0xff00007f, // -1/2^24
};

// Apply internal layer (exact Plonky3 logic from KoalaBearInternalLayerParameters)
pub fn apply_internal_layer_16(state: []F, rc: u32) void {
    // Add round constant to state[0]
    state[0] = state[0].add(F.fromU32(rc));

    // Apply S-box to state[0]
    state[0] = sbox(state[0]);

    // Compute partial sum of state[1..] (exact from Plonky3)
    var part_sum = F.zero;
    for (state[1..]) |elem| {
        part_sum = part_sum.add(elem);
    }

    // Compute full sum
    const full_sum = part_sum.add(state[0]);

    // Apply internal matrix: state[0] = part_sum - state[0] (exact from Plonky3)
    state[0] = part_sum.sub(state[0]);

    // Apply V-based operations for i >= 1 (exact from Plonky3 internal_layer_mat_mul)
    // The diagonal matrix is defined by the vector:
    // V = [-2, 1, 2, 1/2, 3, 4, -1/2, -3, -4, 1/2^8, 1/8, 1/2^24, -1/2^8, -1/8, -1/16, -1/2^24]

    // state[1] += sum
    state[1] = state[1].add(full_sum);

    // state[2] = state[2].double() + sum
    state[2] = state[2].double().add(full_sum);

    // state[3] = state[3].halve() + sum
    state[3] = state[3].halve().add(full_sum);

    // state[4] = sum + state[4].double() + state[4]
    state[4] = full_sum.add(state[4].double()).add(state[4]);

    // state[5] = sum + state[5].double().double()
    state[5] = full_sum.add(state[5].double().double());

    // state[6] = sum - state[6].halve()
    state[6] = full_sum.sub(state[6].halve());

    // state[7] = sum - (state[7].double() + state[7])
    state[7] = full_sum.sub(state[7].double().add(state[7]));

    // state[8] = sum - state[8].double().double()
    state[8] = full_sum.sub(state[8].double().double());

    // state[9] = state[9].div_2exp_u64(8) + sum
    state[9] = state[9].div2exp(8).add(full_sum);

    // state[10] = state[10].div_2exp_u64(3) + sum
    state[10] = state[10].div2exp(3).add(full_sum);

    // state[11] = state[11].div_2exp_u64(24) + sum
    state[11] = state[11].div2exp(24).add(full_sum);

    // state[12] = state[12].div_2exp_u64(8)
    // state[12] = sum - state[12]
    state[12] = state[12].div2exp(8);
    state[12] = full_sum.sub(state[12]);

    // state[13] = state[13].div_2exp_u64(3)
    // state[13] = sum - state[13]
    state[13] = state[13].div2exp(3);
    state[13] = full_sum.sub(state[13]);

    // state[14] = state[14].div_2exp_u64(4)
    // state[14] = sum - state[14]
    state[14] = state[14].div2exp(4);
    state[14] = full_sum.sub(state[14]);

    // state[15] = state[15].div_2exp_u64(24)
    // state[15] = sum - state[15]
    state[15] = state[15].div2exp(24);
    state[15] = full_sum.sub(state[15]);
}

fn apply_internal_layer_24(state: []F, rc: u32) void {
    // Add round constant to state[0]
    state[0] = state[0].add(F.fromU32(rc));

    // Apply S-box to state[0]
    state[0] = sbox(state[0]);

    // Compute partial sum of state[1..] (exact from Plonky3)
    var part_sum = F.zero;
    for (state[1..]) |elem| {
        part_sum = part_sum.add(elem);
    }

    // Compute full sum
    const full_sum = part_sum.add(state[0]);

    // Apply internal matrix: state[0] = part_sum - state[0] (exact from Plonky3)
    state[0] = part_sum.sub(state[0]);

    // Apply V-based operations for i >= 1 (exact from Plonky3 for 24-width)
    // The diagonal matrix is defined by the vector:
    // V = [-2, 1, 2, 1/2, 3, 4, -1/2, -3, -4, 1/2^8, 1/4, 1/8, 1/16, 1/32, 1/64, 1/2^24, -1/2^8, -1/8, -1/16, -1/32, -1/64, -1/2^7, -1/2^9, -1/2^24]

    // state[1] += sum
    state[1] = state[1].add(full_sum);

    // state[2] = state[2].double() + sum
    state[2] = state[2].double().add(full_sum);

    // state[3] = state[3].halve() + sum
    state[3] = state[3].halve().add(full_sum);

    // state[4] = sum + state[4].double() + state[4]
    state[4] = full_sum.add(state[4].double()).add(state[4]);

    // state[5] = sum + state[5].double().double()
    state[5] = full_sum.add(state[5].double().double());

    // state[6] = sum - state[6].halve()
    state[6] = full_sum.sub(state[6].halve());

    // state[7] = sum - (state[7].double() + state[7])
    state[7] = full_sum.sub(state[7].double().add(state[7]));

    // state[8] = sum - state[8].double().double()
    state[8] = full_sum.sub(state[8].double().double());

    // state[9] = state[9].div_2exp_u64(8) + sum
    state[9] = state[9].div2exp(8).add(full_sum);

    // state[10] = state[10].div_2exp_u64(2) + sum
    state[10] = state[10].div2exp(2).add(full_sum);

    // state[11] = state[11].div_2exp_u64(3) + sum
    state[11] = state[11].div2exp(3).add(full_sum);

    // state[12] = state[12].div_2exp_u64(4) + sum
    state[12] = state[12].div2exp(4).add(full_sum);

    // state[13] = state[13].div_2exp_u64(5) + sum
    state[13] = state[13].div2exp(5).add(full_sum);

    // state[14] = state[14].div_2exp_u64(6) + sum
    state[14] = state[14].div2exp(6).add(full_sum);

    // state[15] = state[15].div_2exp_u64(24) + sum
    state[15] = state[15].div2exp(24).add(full_sum);

    // state[16] = state[16].div_2exp_u64(8)
    // state[16] = sum - state[16]
    state[16] = state[16].div2exp(8);
    state[16] = full_sum.sub(state[16]);

    // state[17] = state[17].div_2exp_u64(3)
    // state[17] = sum - state[17]
    state[17] = state[17].div2exp(3);
    state[17] = full_sum.sub(state[17]);

    // state[18] = state[18].div_2exp_u64(4)
    // state[18] = sum - state[18]
    state[18] = state[18].div2exp(4);
    state[18] = full_sum.sub(state[18]);

    // state[19] = state[19].div_2exp_u64(5)
    // state[19] = sum - state[19]
    state[19] = state[19].div2exp(5);
    state[19] = full_sum.sub(state[19]);

    // state[20] = state[20].div_2exp_u64(6)
    // state[20] = sum - state[20]
    state[20] = state[20].div2exp(6);
    state[20] = full_sum.sub(state[20]);

    // state[21] = state[21].div_2exp_u64(7)
    // state[21] = sum - state[21]
    state[21] = state[21].div2exp(7);
    state[21] = full_sum.sub(state[21]);

    // state[22] = state[22].div_2exp_u64(9)
    // state[22] = sum - state[22]
    state[22] = state[22].div2exp(9);
    state[22] = full_sum.sub(state[22]);

    // state[23] = state[23].div_2exp_u64(24)
    // state[23] = sum - state[23]
    state[23] = state[23].div2exp(24);
    state[23] = full_sum.sub(state[23]);
}

// Apply external layer (exact Plonky3 logic)
pub fn apply_external_layer_16(state: []F, rcs: [16]u32) void {
    // Add round constants
    for (0..16) |i| {
        state[i] = state[i].add(F.fromU32(rcs[i]));
    }

    // Apply S-box to all elements
    for (state) |*elem| {
        elem.* = sbox(elem.*);
    }

    // Apply MDS matrix in 4x4 blocks (first step)
    for (0..4) |i| {
        apply_mat4(state, i * 4);
    }

    // Apply outer circulant matrix (second step)
    // Precompute the four sums of every four elements
    var sums: [4]F = undefined;
    for (0..4) |k| {
        sums[k] = F.zero;
        var j: usize = 0;
        while (j < 16) : (j += 4) {
            sums[k] = sums[k].add(state[j + k]);
        }
    }

    // Add the appropriate sum to each element
    for (0..16) |i| {
        state[i] = state[i].add(sums[i % 4]);
    }
}

fn apply_external_layer_24(state: []F, rcs: [24]u32) void {
    // Add round constants
    for (0..24) |i| {
        state[i] = state[i].add(F.fromU32(rcs[i]));
    }

    // Apply S-box to all elements
    for (state) |*elem| {
        elem.* = sbox(elem.*);
    }

    // Apply MDS matrix in 4x4 blocks (first step)
    for (0..6) |i| {
        apply_mat4(state, i * 4);
    }

    // Apply outer circulant matrix (second step)
    // Precompute the four sums of every four elements
    var sums: [4]F = undefined;
    for (0..4) |k| {
        sums[k] = F.zero;
        var j: usize = 0;
        while (j < 24) : (j += 4) {
            sums[k] = sums[k].add(state[j + k]);
        }
    }

    // Add the appropriate sum to each element
    for (0..24) |i| {
        state[i] = state[i].add(sums[i % 4]);
    }
}

// MDS light permutation (exact from Plonky3)
pub fn mds_light_permutation_16(state: []F) void {
    // First, apply M_4 to each consecutive four elements of the state
    for (0..4) |i| {
        apply_mat4(state, i * 4);
    }

    // Now, apply the outer circulant matrix
    // Precompute the four sums of every four elements
    var sums: [4]F = undefined;
    for (0..4) |k| {
        sums[k] = F.zero;
        var j: usize = 0;
        while (j < 16) : (j += 4) {
            sums[k] = sums[k].add(state[j + k]);
        }
    }

    // Add the appropriate sum to each element
    for (0..16) |i| {
        state[i] = state[i].add(sums[i % 4]);
    }
}

// Main permutation function for 16-width
pub fn poseidon2_16_plonky3(state: []F) void {
    // Initial MDS transformation (before any rounds)
    mds_light_permutation_16(state);

    // Initial external rounds
    for (0..4) |i| {
        apply_external_layer_16(state, PLONKY3_KOALABEAR_RC16_EXTERNAL_INITIAL[i]);
    }

    // Internal rounds
    for (0..20) |i| {
        apply_internal_layer_16(state, PLONKY3_KOALABEAR_RC16_INTERNAL[i]);
    }

    // Final external rounds
    for (0..4) |i| {
        apply_external_layer_16(state, PLONKY3_KOALABEAR_RC16_EXTERNAL_FINAL[i]);
    }
}

// MDS light permutation for 24-width (exact from Plonky3)
pub fn mds_light_permutation_24(state: []F) void {
    // First, apply M_4 to each consecutive four elements of the state
    for (0..6) |i| { // 24 / 4 = 6 blocks
        apply_mat4(state, i * 4);
    }

    // Now, apply the outer circulant matrix
    // Precompute the four sums of every four elements
    var sums: [4]F = undefined;
    for (0..4) |k| {
        sums[k] = F.zero;
        var j: usize = 0;
        while (j < 24) : (j += 4) {
            sums[k] = sums[k].add(state[j + k]);
        }
    }

    // Add the appropriate sum to each element
    for (0..24) |i| {
        state[i] = state[i].add(sums[i % 4]);
    }
}

// Main permutation function for 24-width
// FIX: Rust applies MDS light BEFORE the first external round for 24-width!
// This matches Rust's external_initial_permute_state which calls mds_light_permutation first.
// We must apply MDS light first to match Rust's behavior.
pub fn poseidon2_24_plonky3(state: []F) void {
    poseidon2_24_plonky3_with_mds_light(state, true); // Apply MDS light first (matching Rust)
}

// Main permutation function for 24-width with option to skip MDS light (for testing)
// FIX: Rust applies MDS light BEFORE the first external round for 24-width!
// This matches Rust's external_initial_permute_state which calls mds_light_permutation first.
pub fn poseidon2_24_plonky3_with_mds_light(state: []F, apply_mds_light: bool) void {
    // CRITICAL FIX: Rust applies MDS light BEFORE the first external round for 24-width!
    // This matches Rust's external_initial_permute_state behavior.
    // For 24-width, we should ALWAYS apply MDS light first (matching Rust).
    // The apply_mds_light parameter is kept for backward compatibility but should be true for 24-width.
    if (apply_mds_light) {
        mds_light_permutation_24(state);
    }

    // Initial external rounds (4 rounds)
    // CRITICAL: Rust's external_terminal_permute_state applies MDS light INSIDE each round
    // So each external round does: add_rc_and_sbox, then mds_light_permutation
    // NOT: add_rc_and_sbox, then full MDS matrix
    for (0..4) |i| {
        // Add round constants
        for (0..24) |j| {
            state[j] = state[j].add(F.fromU32(PLONKY3_KOALABEAR_RC24_EXTERNAL_INITIAL[i][j]));
        }
        // Apply S-box to all elements
        for (state) |*elem| {
            elem.* = sbox(elem.*);
        }
        // CRITICAL FIX: Apply MDS light (not full MDS matrix) - matching Rust's external_terminal_permute_state
        mds_light_permutation_24(state);
    }

    // Internal rounds (23 rounds)
    for (0..23) |i| {
        apply_internal_layer_24(state, PLONKY3_KOALABEAR_RC24_INTERNAL[i]);
    }

    // Final external rounds (4 rounds)
    // CRITICAL: Rust's external_terminal_permute_state applies MDS light INSIDE each round
    // So each external round does: add_rc_and_sbox, then mds_light_permutation
    // NOT: add_rc_and_sbox, then full MDS matrix
    for (0..4) |i| {
        // Add round constants
        for (0..24) |j| {
            state[j] = state[j].add(F.fromU32(PLONKY3_KOALABEAR_RC24_EXTERNAL_FINAL[i][j]));
        }
        // Apply S-box to all elements
        for (state) |*elem| {
            elem.* = sbox(elem.*);
        }
        // CRITICAL FIX: Apply MDS light (not full MDS matrix) - matching Rust's external_terminal_permute_state
        mds_light_permutation_24(state);
    }
}

// Wrapper structs for compatibility
pub const Poseidon2KoalaBear16Plonky3 = struct {
    pub const Field = F;

    pub fn permutation(state: []F) void {
        poseidon2_16_plonky3(state);
    }

    pub fn compress(_: usize, input: []const u32) [8]u32 {
        var state: [16]F = undefined;
        var padded_input: [16]F = undefined;

        // Convert input to field elements and pad
        for (0..@min(input.len, 16)) |i| {
            const fe = F.fromU32(input[i]);
            state[i] = fe;
            padded_input[i] = fe;
        }

        // Pad with zeros if input is shorter than 16
        for (input.len..16) |i| {
            state[i] = F.zero;
            padded_input[i] = F.zero;
        }

        // Apply permutation
        poseidon2_16_plonky3(&state);

        // Feed-forward: Add the input back into the state element-wise (matching Rust's poseidon_compress)
        for (0..16) |i| {
            state[i] = state[i].add(padded_input[i]);
        }

        // Convert back to u32 and return first 8 elements
        var result: [8]u32 = undefined;
        for (0..8) |i| {
            result[i] = state[i].toU32();
        }

        return result;
    }

    pub fn toMontgomery(mont: *F, value: u32) void {
        mont.* = F.fromU32(value);
    }

    pub fn toNormal(mont: F) u32 {
        return mont.toU32();
    }
};

pub const Poseidon2KoalaBear24Plonky3 = struct {
    pub const Field = F;

    pub fn permutation(state: []F) void {
        poseidon2_24_plonky3(state);
    }

    pub fn compress(_: usize, input: []const u32) [24]u32 {
        var state: [24]F = undefined;
        var padded_input: [24]F = undefined;

        // Convert input to field elements and pad
        for (0..@min(input.len, 24)) |i| {
            const fe = F.fromU32(input[i]);
            state[i] = fe;
            padded_input[i] = fe;
        }

        // Pad with zeros if input is shorter than 24
        for (input.len..24) |i| {
            state[i] = F.zero;
            padded_input[i] = F.zero;
        }

        // Apply permutation (matching Rust's perm.permute_mut(&mut state))
        poseidon2_24_plonky3(&state);

        // Feed-forward: Add the input back into the state element-wise (matching Rust's poseidon_compress)
        for (0..24) |i| {
            state[i] = state[i].add(padded_input[i]);
        }

        // Convert back to u32 and return full state (caller will slice to output_len)
        var result: [24]u32 = undefined;
        for (0..24) |i| {
            result[i] = state[i].toU32();
        }

        return result;
    }

    pub fn toMontgomery(mont: *F, value: u32) void {
        mont.* = F.fromU32(value);
    }

    pub fn toNormal(mont: F) u32 {
        return mont.toU32();
    }
};

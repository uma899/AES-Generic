// Nb = 4 always. Total key-schedule words = Nb*(NR+1).
// round_keys_flat holds (NR+1) concatenated 128-bit round keys,
// MSB-first: round_keys_flat[RK_WIDTH-1 -: 128] = round_key[0]
//            round_keys_flat[127:0]             = round_key[NR]

/*
If you call the same function three times in your code, the synthesis tool will build three separate, physical blocks of 
combinational logic on your FPGA/ASIC. It does not "share" the logic gates.
*/
module key_expansion #(
    parameter NK = 8,     // key length in 32-bit words: 4, 6, or 8
    parameter NR = 14     // number of rounds: 10, 12, or 14
) (
    input  wire [NK*32-1:0]        key,
    output wire [128*(NR+1)-1:0]   round_keys_flat
);

    localparam integer TOTAL_WORDS = 4 * (NR + 1);
    localparam integer RK_WIDTH    = 128 * (NR + 1);

    // ---- Rcon constants (word form: byte,00,00,00), idx = 1..10 ----
    // idx=10 is only reached by AES-128 (NK=4, Nr=10 -> words up to i=40,
    // i/NK=10). AES-192 needs up to idx=8, AES-256 up to idx=7.
    function [31:0] rcon_word;
        input integer idx;
        reg [7:0] rc;
        begin
            case (idx)
                1:  rc = 8'h01;
                2:  rc = 8'h02;
                3:  rc = 8'h04;
                4:  rc = 8'h08;
                5:  rc = 8'h10;
                6:  rc = 8'h20;
                7:  rc = 8'h40;
                8:  rc = 8'h80;
                9:  rc = 8'h1b;
                10: rc = 8'h36;
                default: rc = 8'h00;
            endcase
            rcon_word = {rc, 24'h000000};
        end
    endfunction

    function [31:0] rot_word;
        input [31:0] w;
        begin
            rot_word = {w[23:0], w[31:24]};
        end
    endfunction

    // word array w[0..TOTAL_WORDS-1]
    wire [31:0] w [0:TOTAL_WORDS-1];

    // initial NK words come directly from the key input
    genvar j;
    generate
        for (j = 0; j < NK; j = j + 1) begin : INIT_WORDS
            assign w[j] = key[(NK - j)*32 - 1 -: 32];
        end
    endgenerate

    genvar i;
    generate
        for (i = NK; i < TOTAL_WORDS; i = i + 1) begin : KEY_SCHED
            wire [31:0] temp_pre = w[i-1];

            if ((i % NK) == 0) begin : RCON_STEP
                // temp = SubWord(RotWord(temp_pre)) ^ Rcon(i/NK)
                wire [31:0] temp_rot = rot_word(temp_pre);
                wire [7:0]  sb_out0, sb_out1, sb_out2, sb_out3;

                sbox u_sb0 (.in(temp_rot[31:24]), .out(sb_out0));
                sbox u_sb1 (.in(temp_rot[23:16]), .out(sb_out1));
                sbox u_sb2 (.in(temp_rot[15:8]),  .out(sb_out2));
                sbox u_sb3 (.in(temp_rot[7:0]),   .out(sb_out3));

                assign w[i] = w[i-NK] ^ ({sb_out0, sb_out1, sb_out2, sb_out3} ^ rcon_word(i / NK));
            end
            else if ((NK > 6) && ((i % NK) == 4)) begin : SUBWORD_STEP
                // AES-256 only: extra SubWord (no RotWord, no Rcon) at i%NK==4
                wire [7:0] sb_out0, sb_out1, sb_out2, sb_out3;

                sbox u_sb0 (.in(temp_pre[31:24]), .out(sb_out0));
                sbox u_sb1 (.in(temp_pre[23:16]), .out(sb_out1));
                sbox u_sb2 (.in(temp_pre[15:8]),  .out(sb_out2));
                sbox u_sb3 (.in(temp_pre[7:0]),   .out(sb_out3));

                assign w[i] = w[i-NK] ^ {sb_out0, sb_out1, sb_out2, sb_out3};
            end
            else begin : PLAIN_STEP
                assign w[i] = w[i-NK] ^ temp_pre;
            end
        end
    endgenerate

    genvar r;
    generate
        for (r = 0; r <= NR; r = r + 1) begin : ROUND_KEYS
            assign round_keys_flat[RK_WIDTH - 1 - r*128 -: 128] =
                   {w[4*r], w[4*r+1], w[4*r+2], w[4*r+3]};
        end
    endgenerate

endmodule

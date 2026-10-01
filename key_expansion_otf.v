// key_expansion_otf.v -- On-the-fly (iterative) AES key schedule
// Produces ONE round key per clock cycle, reusing a small, fixed
// set of SubWord hardware instead of the fully-unrolled parallel
// key_expansion.v (which computes all NR+1 round keys at once
// and instantiates a separate sbox for every substitution point
// in the whole schedule -- ~52 sbox instances for AES-256).
//
// Supports AES-128 (NK=4,NR=10), AES-192 (NK=6,NR=12),
// AES-256 (NK=8,NR=14), same as key_expansion.v.
//
// ---- Why this needs care for AES-192 (NK=6) ----
// Round keys are always 4 words (Nb=4). For NK=4 and NK=8, NK is
// a multiple of Nb, so each new 4-word generation step produces
// exactly one new round key, cleanly. NK=6 is NOT a multiple of
// 4, so a round key can be made of 2 words "left over" from the
// previous generation step plus 2 freshly generated words. This
// module handles that case explicitly (see ROUND_KEY_MUX below);
// NK=4 and NK=8 both reduce to "round key = the 4 freshly
// generated words" with no leftover-mixing needed.

module key_expansion_otf #(
    parameter NK = 8,     // key length in 32-bit words: 4, 6, or 8
    parameter NR = 14     // number of rounds: 10, 12, or 14
) (
    input  wire              clk,
    input  wire              rst_n,
    input  wire              load,
    input  wire              next,
    input  wire [NK*32-1:0]  key,
    output reg  [127:0]      round_key,
    output reg  [4:0]        rk_idx
);

    localparam integer FREE = NK / 4;   // # round keys available with no generation

    initial begin
        if (NK != 4 && NK != 6 && NK != 8) begin
            $display("ERROR: key_expansion_otf NK must be 4, 6, or 8 (got %0d)", NK);
            $finish;
        end
    end

    // ---- Rcon / RotWord helpers (same math as key_expansion.v) ----
    function [31:0] rcon_word;
        input integer idx;
        reg [7:0] rc;
        begin
            case (idx)
                1:  rc = 8'h01; 2:  rc = 8'h02; 3:  rc = 8'h04; 4:  rc = 8'h08;
                5:  rc = 8'h10; 6:  rc = 8'h20; 7:  rc = 8'h40; 8:  rc = 8'h80;
                9:  rc = 8'h1b; 10: rc = 8'h36;
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

    // Rolling window of the NK most-recently-produced words. Declared at a
    // fixed size of 8 (the largest supported NK) regardless of the actual
    // NK, so that ordinary (non-generate) `if` branches referencing e.g.
    // hist[4]..hist[7] stay elaboration-safe even when NK=4 -- those
    // branches are only ever reached at runtime when NK actually is 8, but
    // the array declaration has to admit the index either way.
    reg [31:0] hist [0:7];
    reg [5:0]  g;    // next global word index to generate once past FREE

    // ---- one 4-word generation step: combinational, reused every cycle ----
    wire [31:0] new_w [0:3];

    genvar m;
    generate
        for (m = 0; m < 4; m = m + 1) begin : SUBWORD_UNIT
            wire [31:0] prev_word;   // the word immediately before this one in the full sequence
            if (m == 0) begin : PW0
                assign prev_word = hist[NK-1];
            end else begin : PWN
                assign prev_word = new_w[m-1];
            end

            wire is_rcon = (((g + m) % NK) == 0);
            wire is_subw = (NK > 6) && (((g + m) % NK) == 4);

            wire [31:0] sbox_in = is_rcon ? rot_word(prev_word) : prev_word;
            wire [7:0]  sbox_o0, sbox_o1, sbox_o2, sbox_o3;
            sbox u_sb0 (.in(sbox_in[31:24]), .out(sbox_o0));
            sbox u_sb1 (.in(sbox_in[23:16]), .out(sbox_o1));
            sbox u_sb2 (.in(sbox_in[15:8]),  .out(sbox_o2));
            sbox u_sb3 (.in(sbox_in[7:0]),   .out(sbox_o3));
            wire [31:0] subword_out = {sbox_o0, sbox_o1, sbox_o2, sbox_o3};

            wire [31:0] temp = is_rcon ? (subword_out ^ rcon_word((g + m) / NK)) :
                                is_subw ? subword_out :
                                          prev_word;

            assign new_w[m] = hist[m] ^ temp;
        end
    endgenerate

    // ---- shifted window for next cycle: drop oldest 4, append new 4 ----
    wire [31:0] shifted_hist [0:7];
    genvar k;
    generate
        for (k = 0; k < 8; k = k + 1) begin : SHIFT
            if (k < NK - 4)
                assign shifted_hist[k] = hist[k+4];
            else if (k < NK)
                assign shifted_hist[k] = new_w[k - (NK - 4)];
            else
                assign shifted_hist[k] = 32'h0;   // unused slot for NK<8
        end
    endgenerate

    // ---- round key assembly once past the free zone ----
    // NK=4 and NK=8: the freshly generated 4 words ARE the round key.
    // NK=6 (the one case where NK isn't a multiple of 4): the round key
    // is 2 leftover words from the previous window plus the first 2
    // freshly generated words -- see module header for why.
    wire [127:0] generated_round_key;
    generate
        if (NK == 6) begin : RK_MIX_NK6
            assign generated_round_key = {hist[4], hist[5], new_w[0], new_w[1]};
        end else begin : RK_PLAIN
            assign generated_round_key = {new_w[0], new_w[1], new_w[2], new_w[3]};
        end
    endgenerate

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            rk_idx    <= 5'd0;
            g         <= 6'd0;
            round_key <= 128'h0;
            hist[0] <= 32'h0; hist[1] <= 32'h0; hist[2] <= 32'h0; hist[3] <= 32'h0;
            hist[4] <= 32'h0; hist[5] <= 32'h0; hist[6] <= 32'h0; hist[7] <= 32'h0;
        end
        else if (load) begin
            hist[0] <= (0 < NK) ? key[(NK-0)*32-1 -: 32] : 32'h0;
            hist[1] <= (1 < NK) ? key[(NK-1)*32-1 -: 32] : 32'h0;
            hist[2] <= (2 < NK) ? key[(NK-2)*32-1 -: 32] : 32'h0;
            hist[3] <= (3 < NK) ? key[(NK-3)*32-1 -: 32] : 32'h0;
            hist[4] <= (4 < NK) ? key[(NK-4)*32-1 -: 32] : 32'h0;
            hist[5] <= (5 < NK) ? key[(NK-5)*32-1 -: 32] : 32'h0;
            hist[6] <= (6 < NK) ? key[(NK-6)*32-1 -: 32] : 32'h0;
            hist[7] <= (7 < NK) ? key[(NK-7)*32-1 -: 32] : 32'h0;
            g         <= NK;
            rk_idx    <= 5'd0;
            // round key 0 is always the first 4 words of the key, for every NK
            round_key <= { key[(NK-0)*32-1 -: 32], key[(NK-1)*32-1 -: 32],
                            key[(NK-2)*32-1 -: 32], key[(NK-3)*32-1 -: 32] };
        end
        else if (next) begin
            if ((rk_idx + 1) < FREE) begin
                // Only ever reachable when NK==8 (FREE==2): round key 1 is
                // also part of the originally loaded key, no generation.
                rk_idx    <= rk_idx + 5'd1;
                round_key <= {hist[4], hist[5], hist[6], hist[7]};
            end else begin
                // Perform one real generation step.
                hist[0] <= shifted_hist[0]; hist[1] <= shifted_hist[1];
                hist[2] <= shifted_hist[2]; hist[3] <= shifted_hist[3];
                hist[4] <= shifted_hist[4]; hist[5] <= shifted_hist[5];
                hist[6] <= shifted_hist[6]; hist[7] <= shifted_hist[7];
                g         <= g + 6'd4;
                rk_idx    <= rk_idx + 5'd1;
                round_key <= generated_round_key;
            end
        end
    end

endmodule

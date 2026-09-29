module sub_bytes (
    input  wire [127:0] state_in,
    output wire [127:0] state_out
);

    genvar i;
    generate
        for (i = 0; i < 16; i = i + 1) begin : SB_BYTES
            sbox u_sbox (
                .in  ( state_in [127 - i*8 -: 8] ),
                .out ( state_out[127 - i*8 -: 8] )
            );
        end
    endgenerate

endmodule

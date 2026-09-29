module mix_columns (
    input  wire [127:0] state_in,
    output wire [127:0] state_out
);

    function [7:0] xtime;
        input [7:0] a;
        begin
            xtime = a[7] ? ((a << 1) ^ 8'h1b) : (a << 1);
        end
    endfunction

    function [7:0] gmul3;
        input [7:0] a;
        begin
            gmul3 = xtime(a) ^ a;
        end
    endfunction

    function [7:0] getb;
        input [127:0] s;
        input integer i;
        begin
            getb = s[127 - i*8 -: 8];
        end
    endfunction

    genvar c;
    generate
        for (c = 0; c < 4; c = c + 1) begin : MC_COL
            wire [7:0] b0 = getb(state_in, 4*c + 0);
            wire [7:0] b1 = getb(state_in, 4*c + 1);
            wire [7:0] b2 = getb(state_in, 4*c + 2);
            wire [7:0] b3 = getb(state_in, 4*c + 3);

            wire [7:0] n0 = xtime(b0) ^ gmul3(b1) ^ b2         ^ b3;
            wire [7:0] n1 = b0        ^ xtime(b1) ^ gmul3(b2)  ^ b3;
            wire [7:0] n2 = b0        ^ b1         ^ xtime(b2) ^ gmul3(b3);
            wire [7:0] n3 = gmul3(b0) ^ b1          ^ b2        ^ xtime(b3);

            assign state_out[127 - (4*c+0)*8 -: 8] = n0;
            assign state_out[127 - (4*c+1)*8 -: 8] = n1;
            assign state_out[127 - (4*c+2)*8 -: 8] = n2;
            assign state_out[127 - (4*c+3)*8 -: 8] = n3;
        end
    endgenerate

endmodule

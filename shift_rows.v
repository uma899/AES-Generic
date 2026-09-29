module shift_rows (
    input  wire [127:0] state_in,
    output wire [127:0] state_out
);

    // extract byte i (0..15) from a 128-bit state word
    function [7:0] getb;
        input [127:0] s;
        input integer i;
        begin
            getb = s[127 - i*8 -: 8];
        end
    endfunction

    // Row0: no shift        -> new[0,4,8,12]  = old[0,4,8,12]
    // Row1: shift left 1    -> new[1,5,9,13]  = old[5,9,13,1]
    // Row2: shift left 2    -> new[2,6,10,14] = old[10,14,2,6]
    // Row3: shift left 3    -> new[3,7,11,15] = old[15,3,7,11]
    assign state_out[127:120] = getb(state_in, 0);
    assign state_out[119:112] = getb(state_in, 5);
    assign state_out[111:104] = getb(state_in, 10);
    assign state_out[103:96]  = getb(state_in, 15);

    assign state_out[95:88]   = getb(state_in, 4);
    assign state_out[87:80]   = getb(state_in, 9);
    assign state_out[79:72]   = getb(state_in, 14);
    assign state_out[71:64]   = getb(state_in, 3);

    assign state_out[63:56]   = getb(state_in, 8);
    assign state_out[55:48]   = getb(state_in, 13);
    assign state_out[47:40]   = getb(state_in, 2);
    assign state_out[39:32]   = getb(state_in, 7);

    assign state_out[31:24]   = getb(state_in, 12);
    assign state_out[23:16]   = getb(state_in, 1);
    assign state_out[15:8]    = getb(state_in, 6);
    assign state_out[7:0]     = getb(state_in, 11);

endmodule

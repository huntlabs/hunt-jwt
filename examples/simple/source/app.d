import std.stdio;

import jwt;
import std.datetime;
import std.exception;

void main()
{
	string tokenString = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjEiLCJuYW1lIjoiYWxpY2UiLCJlbWFpbCI6ImFsaWNlQGdtYWlsLmNvbSIsInBob25lX251bWJlciI6IjE4ODAwMDAwMDAxIiwibmJmIjoxNTA5NDY0MzQwLCJleHAiOjE1MTAwNjkxNDAsImlhdCI6MTUwOTQ2NDM0MH0.nV7duR2gWHA3TB9xPhP1WWhDpXRn1GA_k8_zBBirT6g";

    Token tk = decode(tokenString);

    writeln(tk.header.json());
    writeln(tk.claims.json());

    tk = verify(tokenString, "secret", []);
}

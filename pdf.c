#include "pdf.h"
#include <hpdf.h>
#include <stdio.h>

int generate_pdf(const char *pdf_path, const char *pcap, const Stats *st) {
    HPDF_Doc pdf = HPDF_New(NULL, NULL); // create pdf 

    HPDF_Page page = HPDF_AddPage(pdf); // add page and set to a4
    HPDF_Page_SetSize(page, HPDF_PAGE_SIZE_A4, HPDF_PAGE_PORTRAIT);

    HPDF_Font font = HPDF_GetFont(pdf, "Times-Roman", NULL); // set font and size
    HPDF_Page_SetFontAndSize(page, font, 16);

    HPDF_Page_BeginText(page); // draw title text 
    HPDF_Page_MoveTextPos(page, 50, 795);
    HPDF_Page_ShowText(page, "Analiza ruchu sieci");
    HPDF_Page_EndText(page);

    HPDF_Page_SetFontAndSize(page, font, 11); // set body text size
    int y = 750; // startpos

    char b0[128], b1[128], b2[128], b3[128], b4[128], b5[128], b6[128]; // stats buffers
    snprintf(b0, sizeof(b0), "Plik: %s", pcap);
    snprintf(b1, sizeof(b1), "pakietow: %d/ bajtow: %ld", st->total_packets, st->total_bytes);
    snprintf(b2, sizeof(b2), "TCP: %d, bajty: %ld", st->tcp_packets, st->tcp_bytes);
    snprintf(b3, sizeof(b3), "UDP: %d, bajty: %ld", st->udp_packets, st->udp_bytes);
    snprintf(b4, sizeof(b4), "TCP RST: %d", st->rst_count);
    snprintf(b5, sizeof(b5), "Top port: %d, %d pakietow", st->top_port, st->top_port_hits);
    snprintf(b6, sizeof(b6), "Anomalie: %s", st->suspicious_flag ? "TAK" : "NIE");

    const char *lines[7] = { b0, b1, b2, b3, b4, b5, b6 };

    for (int i = 0; i < 7; i++) {   // draw stats 
        HPDF_Page_BeginText(page);
        HPDF_Page_MoveTextPos(page, 50, y);
        HPDF_Page_ShowText(page, lines[i]);
        HPDF_Page_EndText(page);
        y -= 18;
    }

    // chart 1 
    HPDF_Image img1 = HPDF_LoadPngImageFromFile(pdf, "tcp_udp.png");
    if (img1) {
        HPDF_Page_DrawImage(page, img1, 60, 355, 420, 260);
    }

    // chart 2
    HPDF_Image img2 = HPDF_LoadPngImageFromFile(pdf, "top_ports.png");
    if (img2) {
        HPDF_Page_DrawImage(page, img2, 60, 65, 440, 260);
    }

    HPDF_SaveToFile(pdf, pdf_path); // save pdf and quit 
    HPDF_Free(pdf);
    return 0;
}
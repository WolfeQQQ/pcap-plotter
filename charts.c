#include "charts.h"
#include <gd.h>
#include <gdfonts.h>
#include <stdio.h>

static int draw_tcp_udp_chart(const Stats *st) {
    // set width and height
    int width = 600;
    int height = 400;

    gdImagePtr im = gdImageCreate(width, height); // create image

    // background and colors
    gdImageColorAllocate(im, 255, 255, 255); 
    int black = gdImageColorAllocate(im, 0, 0, 0);
    int blue  = gdImageColorAllocate(im, 50, 120, 220);
    int green = gdImageColorAllocate(im, 40, 180, 90);

    // x and y axis
    gdImageLine(im, 80, 320, 520, 320, black);
    gdImageLine(im, 80, 60, 80, 320, black);

    // title
    gdImageString(im, gdFontGetSmall(), 180, 25, (unsigned char *)"pakiety: TCP vs UDP", black);

    // max value
    int max_val = st->tcp_packets > st->udp_packets ? st->tcp_packets : st->udp_packets;
    if (max_val < 1) max_val = 1;

    // scale the bars
    int tcp_h = (st->tcp_packets * 220) / max_val;
    int udp_h = (st->udp_packets * 220) / max_val;

    //TCP bar
    gdImageFilledRectangle(im, 150, 320 - tcp_h, 240, 320, blue);
    gdImageRectangle(im, 150, 320 - tcp_h, 240, 320, black);
    gdImageString(im, gdFontGetSmall(), 180, 330, (unsigned char *)"TCP", black);

    char buf_tcp[64];
    snprintf(buf_tcp, sizeof(buf_tcp), "%d", st->tcp_packets);
    gdImageString(im, gdFontGetSmall(), 180, 320 - tcp_h - 15, (unsigned char *)buf_tcp, black);

    // UDP bar
    gdImageFilledRectangle(im, 350, 320 - udp_h, 440, 320, green);
    gdImageRectangle(im, 350, 320 - udp_h, 440, 320, black);
    gdImageString(im, gdFontGetSmall(), 380, 330, (unsigned char *)"UDP", black);

    char buf_udp[64];
    snprintf(buf_udp, sizeof(buf_udp), "%d", st->udp_packets);
    gdImageString(im, gdFontGetSmall(), 380, 320 - udp_h - 15, (unsigned char *)buf_udp, black);

    // open out file and save chart
    FILE *out = fopen("tcp_udp.png", "wb");
    gdImagePng(im, out);
    fclose(out);
    gdImageDestroy(im);
    return 0; 
}

static int draw_ports_chart(const Stats *st) {
    // set width and height
    int width = 650;
    int height = 400;

    gdImagePtr im = gdImageCreate(width, height); // create image

    // background and colors
    gdImageColorAllocate(im, 255, 255, 255); // tlo biale
    int black  = gdImageColorAllocate(im, 0, 0, 0);
    int green = gdImageColorAllocate(im, 40, 180, 90);

    // x and y axis 
    gdImageLine(im, 70, 320, 600, 320, black);
    gdImageLine(im, 70, 60, 70, 320, black);

    // title
    gdImageString(im, gdFontGetSmall(), 210, 40, (unsigned char *)"top 3 porty", black);

    // max value
    int max_val = st->top_port_counts[0];
    if (max_val < 1) max_val = 1;

    // bars draw loop w/ positioning scaling and drawing
    for (int i = 0; i < TOP_N; i++) {
        int hits = st->top_port_counts[i];
        int port = st->top_ports[i];
        int bar_h = (hits * 220) / max_val;

        int x1 = 100 + i * 95;
        int x2 = x1 + 60;
        int y1 = 320 - bar_h;
        int y2 = 320;

        gdImageFilledRectangle(im, x1, y1, x2, y2, green);
        gdImageRectangle(im, x1, y1, x2, y2, black);

        char port_lbl[32];
        snprintf(port_lbl, sizeof(port_lbl), "P:%d", port);
        gdImageString(im, gdFontGetSmall(), x1 + 8, 330, (unsigned char *)port_lbl, black);

        char hits_lbl[32];
        snprintf(hits_lbl, sizeof(hits_lbl), "%d", hits);
        gdImageString(im, gdFontGetSmall(), x1 + 12, y1 - 15, (unsigned char *)hits_lbl, black);
    }

    //open out file and save chart
    FILE *out = fopen("top_ports.png", "wb");
    gdImagePng(im, out);
    fclose(out);
    gdImageDestroy(im);
    return 0;
}

int generate_charts(const Stats *st) {
    if (draw_tcp_udp_chart(st) != 0) return -1;
    if (draw_ports_chart(st) != 0) return -1;
    return 0;
}
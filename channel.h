#pragma once

struct ChThread {
    char       *dev;
    int        *ch_list;
};

void GetChannelList(char *dev, int **ch_list);
void *ChannelHopping(void *thd);

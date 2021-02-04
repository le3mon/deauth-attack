#include <stdio.h>
#include <string>
#include <regex>
#include <pthread.h>
#include <stdio.h>
#include "channel.h"
using namespace std;

void GetChannelList(char *dev, int **ch_list) {
    char *cmd = new char[48];
    sprintf(cmd, "iwlist %s channel", dev);

    FILE *fp = popen(cmd, "r");
    if(fp == nullptr) {
        printf("popen error\n");
        printf("command is %s\n", cmd);
        exit(-1);
    }

    char *tmp = new char[4000];
    fread(tmp, 4000, 1, fp);
    string buf(tmp);
    regex reg(" ([0-9])+ ");
    sregex_iterator it_begin(buf.begin(), buf.end(), reg);
    sregex_iterator it_end;
    int i = 0;
    for (sregex_iterator it = it_begin;it != it_end;it++, i++) {
        smatch match = *it;
        string match_str = match.str();
        if(i == 0) {
            int ch_num = stoi(match_str);
            *ch_list = new int[ch_num+1];
            (*ch_list)[ch_num] = 0;
        }
        else {
            int ch = stoi(match_str);
            (*ch_list)[i-1] = ch;
        }
    }
    delete []cmd;
    delete []tmp;
}

void *ChannelHopping(void *thd) {
    ChThread *p = reinterpret_cast<ChThread*>(thd);
    char *cmd = new char[48];
    int i = 0;
    while (true) {
        if(p->ch_list[i] == 0)
            i = 0;
        sprintf(cmd, "iwconfig %s channel %d", p->dev, p->ch_list[i]);
        system(cmd);
        i++;
    }
}

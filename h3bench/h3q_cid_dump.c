/*
 * h3q_cid_dump - dump the h3q_cid_map eBPF SOCKHASH map
 *
 * Iterates over all CID entries registered by mod_http3 in the pinned
 * BPF map at /sys/fs/bpf/h3q_cid_map and prints each CID (hex).
 *
 * Build:  cc -o h3q_cid_dump h3q_cid_dump.c
 * Run:    sudo ./h3q_cid_dump
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/bpf.h>

static int sys_bpf(int cmd, union bpf_attr *attr, unsigned int size)
{
    return (int)syscall(__NR_bpf, cmd, attr, size);
}

static int open_pinned(const char *path)
{
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.pathname = (uint64_t)(unsigned long)path;
    return sys_bpf(BPF_OBJ_GET, &attr, sizeof(attr));
}

static int map_get_next_key(int map_fd, const void *key, void *next_key)
{
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd   = (uint32_t)map_fd;
    attr.key      = (uint64_t)(unsigned long)key;
    attr.next_key = (uint64_t)(unsigned long)next_key;
    return sys_bpf(BPF_MAP_GET_NEXT_KEY, &attr, sizeof(attr));
}

static int map_get_info(int map_fd, struct bpf_map_info *info)
{
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.info.bpf_fd   = (uint32_t)map_fd;
    attr.info.info_len  = sizeof(*info);
    attr.info.info      = (uint64_t)(unsigned long)info;
    return sys_bpf(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr));
}

static void hex8(char *out, const unsigned char *data)
{
    int i;
    for (i = 0; i < 8; i++)
        sprintf(out + i * 2, "%02x", data[i]);
    out[16] = '\0';
}

int main(int argc, char **argv)
{
    const char *map_path = "/sys/fs/bpf/h3q_cid_map";
    const char *prog_path = "/sys/fs/bpf/h3q_reuseport";
    int map_fd, prog_fd;
    uint64_t key, next_key;
    int count = 0;
    struct bpf_map_info minfo;
    struct bpf_prog_info pinfo;
    char cid_hex[17];

    if (argc > 1)
        map_path = argv[1];

    /* open the pinned map */
    map_fd = open_pinned(map_path);
    if (map_fd < 0) {
        fprintf(stderr, "cannot open %s: %s\n", map_path, strerror(errno));
        fprintf(stderr, "is the eBPF program loaded? try: sudo bpftool prog show pinned %s\n", prog_path);
        return 1;
    }

    /* map info */
    memset(&minfo, 0, sizeof(minfo));
    if (map_get_info(map_fd, &minfo) == 0) {
        printf("map: %s\n", minfo.name[0] ? minfo.name : "(unnamed)");
        printf("  type:        %u (SOCKHASH=%d)\n", minfo.type, BPF_MAP_TYPE_SOCKHASH);
        printf("  key_size:    %u bytes\n", minfo.key_size);
        printf("  value_size:  %u bytes\n", minfo.value_size);
        printf("  max_entries: %u\n", minfo.max_entries);
        printf("  id:          %u\n", minfo.id);
        printf("\n");
    }

    /* prog info */
    prog_fd = open_pinned(prog_path);
    if (prog_fd >= 0) {
        memset(&pinfo, 0, sizeof(pinfo));
        union bpf_attr attr;
        memset(&attr, 0, sizeof(attr));
        attr.info.bpf_fd  = (uint32_t)prog_fd;
        attr.info.info_len = sizeof(pinfo);
        attr.info.info     = (uint64_t)(unsigned long)&pinfo;
        if (sys_bpf(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr)) == 0) {
            printf("prog: %s\n", pinfo.name[0] ? pinfo.name : "(unnamed)");
            printf("  type:        %u (SK_REUSEPORT=%d)\n", pinfo.type, BPF_PROG_TYPE_SK_REUSEPORT);
            printf("  id:          %u\n", pinfo.id);
            printf("  run_count:   %llu\n", (unsigned long long)pinfo.run_cnt);
            printf("  run_time_ns: %llu\n", (unsigned long long)pinfo.run_time_ns);
            printf("\n");
        }
        close(prog_fd);
    }

    /* iterate all CID keys */
    printf("CID entries:\n");
    memset(&key, 0, sizeof(key));
    if (map_get_next_key(map_fd, NULL, &next_key) != 0) {
        printf("  (empty)\n");
        close(map_fd);
        return 0;
    }

    key = next_key;
    do {
        hex8(cid_hex, (const unsigned char *)&key);
        printf("  [%5d] CID: %s\n", count, cid_hex);
        count++;
    } while (map_get_next_key(map_fd, &key, &next_key) == 0 && (key = next_key, 1));

    printf("\ntotal: %d entries (max %u)\n", count, minfo.max_entries);
    if (count > 0 && minfo.max_entries > 0) {
        printf("usage: %.1f%%\n", 100.0 * count / minfo.max_entries);
    }

    close(map_fd);
    return 0;
}

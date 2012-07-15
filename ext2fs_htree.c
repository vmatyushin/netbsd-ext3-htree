#include <sys/cdefs.h>

#include <sys/param.h>
#include <sys/vnode.h>
#include <sys/namei.h>
#include <sys/buf.h>

#include <ufs/ufs/dir.h>
#include <ufs/ufs/inode.h>
#include <ufs/ufs/ufs_extern.h>

#include <ufs/ext2fs/ext2fs.h>
#include <ufs/ext2fs/ext2fs_extern.h>
#include <ufs/ext2fs/ext2fs_dinode.h>
#include <ufs/ext2fs/ext2fs_dir.h>
#include <ufs/ext2fs/ext2fs_htree.h>

#include <lib/libkern/libkern.h>

/*
 * Check if given directory has HTree index.
 */
int
ext2fs_htree_has_idx(struct inode *ip)
{
	if ((ip->i_e2fs->e2fs.e2fs_features_compat & EXT2F_COMPAT_HTREE) &&
		(ip->i_e2fs_flags & EXT2_HTREE))
		return (1);
	else
		return (0);
}

/*
 * Maximum number of index entries which can fit in the index node.
 */
static uint16_t
ext2fs_htree_get_limit(struct ext2fs_htree_entry *ep)
{
// 	printf("limit %u\n", fs2h16(((struct ext2fs_htree_count *)(ep))->h_entries_max));
	return fs2h16(((struct ext2fs_htree_count *)(ep))->h_entries_max);
}

static void
ext2fs_htree_set_limit(struct ext2fs_htree_entry *ep, uint16_t limit)
{
	((struct ext2fs_htree_count *)(ep))->h_entries_max = h2fs16(limit);
}

/*
 * Number of index entries in the index node.
 */
static uint16_t
ext2fs_htree_get_count(struct ext2fs_htree_entry *ep)
{
// 	printf("count %u\n", fs2h16(((struct ext2fs_htree_count *)(ep))->h_entries_num));
	return fs2h16(((struct ext2fs_htree_count *)(ep))->h_entries_num);
}

static void
ext2fs_htree_set_count(struct ext2fs_htree_entry *ep, uint16_t count)
{
	((struct ext2fs_htree_count *)(ep))->h_entries_num = h2fs16(count);
}

static uint32_t
ext2fs_htree_get_block(struct ext2fs_htree_entry *ep)
{
// 	printf("blk %u\n", fs2h32(ep->h_blk) & 0x00FFFFFF);
	return fs2h32(ep->h_blk) & 0x00FFFFFF;
}

static void
ext2fs_htree_set_block(struct ext2fs_htree_entry *ep, uint32_t blk)
{
	ep->h_blk = h2fs32(blk);
}

static uint32_t
ext2fs_htree_get_hash(struct ext2fs_htree_entry *ep)
{
// 	printf("hash 0x%8X\n", fs2h32(ep->h_hash));
	return fs2h32(ep->h_hash);
}

static void
ext2fs_htree_set_hash(struct ext2fs_htree_entry *ep, uint32_t hash)
{
// 	printf("hash 0x%8X\n", fs2h32(ep->h_hash));
	ep->h_hash = h2fs32(hash);
}

static uint32_t
ext2fs_htree_root_limit(struct inode *ip, int len)
{
	struct m_ext2fs *fs;
	uint32_t space;

	fs = ip->i_e2fs;
	space = fs->e2fs_bsize - EXT2FS_DIRSIZ(1) -
		EXT2FS_DIRSIZ(2) - len;
// 	printf("root limit %lu\n", (space / sizeof(struct ext2fs_htree_entry)));
	return (space / sizeof(struct ext2fs_htree_entry));
}

static uint32_t
ext2fs_htree_node_limit(struct inode *ip)
{
	struct m_ext2fs *fs;
	uint32_t space;

	fs = ip->i_e2fs;
	space = fs->e2fs_bsize - EXT2FS_DIRSIZ(0);
// 	printf("node limit %lu\n", (space / sizeof(struct ext2fs_htree_entry)));
	return (space / sizeof(struct ext2fs_htree_entry));
}

static void
ext2fs_htree_release(struct ext2fs_htree_lookup_info *info)
{
	int i;

	for (i = 0; i < info->h_levels_num; i++) {
		struct buf *bp = info->h_levels[i].h_bp;
		if (bp != NULL)
			brelse(bp, 0);
	}
}

static int
ext2fs_htree_writebuf(struct ext2fs_htree_lookup_info *info)
{
	int i, error;

	for (i = 0; i < info->h_levels_num; i++) {
		struct buf *bp = info->h_levels[i].h_bp;
		error = VOP_BWRITE(bp->b_vp, bp);
		if (error)
			return (error);
	}
	return (0);
}

/*
 * Insert an index entry to the index node.
 */
static void
ext2fs_htree_insert_entry(struct ext2fs_htree_lookup_info *info,
			  uint32_t hash, uint32_t blk)
{
	struct ext2fs_htree_lookup_level *level;
	struct ext2fs_htree_entry *target;
	int entries_num;

	level = &info->h_levels[info->h_levels_num - 1];
	target = level->h_entry + 1;
	entries_num = ext2fs_htree_get_count(level->h_entries);

	memmove(target + 1, target, (char *) (level->h_entries + entries_num) -
		(char *) target);
	ext2fs_htree_set_block(target, blk);
	ext2fs_htree_set_hash(target, hash);
	ext2fs_htree_set_count(level->h_entries, entries_num + 1);
}

/*
 * Perform a binary search of leaf directory block in index by name hash value.
 */
static int
ext2fs_htree_find_leaf(struct vnode *vp, const char *name, int namelen,
		       uint32_t *hash, uint8_t *hash_ver,
		       struct ext2fs_htree_lookup_info *info)
{
	struct ext2fs *fs;
	struct m_ext2fs *m_fs;
	struct buf *bp = NULL;
	struct ext2fs_htree_root *rootp;
	struct ext2fs_htree_entry *entp, *start, *end, *middle, *found;
	struct ext2fs_htree_lookup_level *level_info;
	uint32_t hash_major = 0, hash_minor = 0;
	uint32_t levels, cnt;
	uint8_t hash_version;

	if (name == NULL || info == NULL)
		return (-1);

	fs = &(VTOI(vp)->i_e2fs->e2fs);
	m_fs = VTOI(vp)->i_e2fs;

	if (ext2fs_blkatoff(vp, 0, NULL, &bp) != 0)
		return (-1);

	info->h_levels_num = 1;
	info->h_levels[0].h_bp = bp;
	rootp = (struct ext2fs_htree_root *) bp->b_data;
	if (rootp->h_info.h_hash_version != EXT2_HTREE_LEGACY &&
		rootp->h_info.h_hash_version != EXT2_HTREE_HALF_MD4 &&
		rootp->h_info.h_hash_version != EXT2_HTREE_TEA) {
		printf("hash ver error\n");
		goto find_leaf_error;
	}

// 	printf("vnode %p ver %u, len %u, levels %u\n", rootp,
// 		rootp->h_info.h_hash_version,
// 		rootp->h_info.h_info_len,
// 		rootp->h_info.h_ind_levels);

	hash_version = rootp->h_info.h_hash_version;
	if (hash_version <= EXT2_HTREE_TEA) {
		hash_version += m_fs->e2fs_uhash;
	}
	*hash_ver = hash_version;

	ext2fs_htree_hash(name, namelen, fs->e2fs_hash_seed,
			  hash_version, &hash_major, &hash_minor);
	*hash = hash_major;

// 	printf("name %s, ver %u, hash 0x%8X 0x%8X\n", name,
// 		rootp->h_info.h_hash_version,
// 		hash_major, hash_minor);

	if ((levels = rootp->h_info.h_ind_levels) > 1) {
		printf("ind levels > 1\n");
		goto find_leaf_error;
	}

	entp = (struct ext2fs_htree_entry *) (((char *) &rootp->h_info) +
						rootp->h_info.h_info_len);

	if (ext2fs_htree_get_limit(entp) !=
		ext2fs_htree_root_limit(VTOI(vp), rootp->h_info.h_info_len)) {
		printf("limit != root limit: %u %u\n",
			ext2fs_htree_get_limit(entp),
		        ext2fs_htree_root_limit(VTOI(vp),
						rootp->h_info.h_info_len));
		goto find_leaf_error;
	}

	while (1) {
		cnt = ext2fs_htree_get_count(entp);
		if ((cnt == 0) || (cnt > ext2fs_htree_get_limit(entp))) {
			printf("cnt error\n");
			goto find_leaf_error;
		}

// 		printf("level %u, search\n", levels);

		start = entp + 1;
		end = entp + cnt - 1;
		while (start <= end) {
			middle = start + (end - start) / 2;
			if (ext2fs_htree_get_hash(middle) > hash_major) {
				end = middle - 1;
			} else {
				start = middle + 1;
			}
		}
		found = start - 1;

		level_info = &(info->h_levels[info->h_levels_num - 1]);
		level_info->h_bp = bp;
		level_info->h_entries = entp;
		level_info->h_entry = found;
		
// 		printf("found, level %u\n", levels);

		if (levels == 0) {
// 			printf("found, off %ld, hash 0x%8X, blk %u\n",
// 				found - entp, found->h_hash,
// 				found->h_blk);
			return (0);
		}
		levels--;
		if (ext2fs_blkatoff(vp,
			ext2fs_htree_get_block(found) * m_fs->e2fs_bsize,
			NULL, &bp) != 0) {
			printf("blkatoff error\n");
			goto find_leaf_error;
		}
// 		printf("read block %u\n", ext2fs_htree_get_block(found));
		entp = ((struct ext2fs_htree_node *) bp->b_data)->h_entries;

		info->h_levels_num++;
		info->h_levels[info->h_levels_num - 1].h_bp = bp;

		if (ext2fs_htree_get_limit(entp) !=
			ext2fs_htree_node_limit(VTOI(vp))) {
			printf("limit != node limit\n");
			goto find_leaf_error;
		}
	}

find_leaf_error:
	printf("vnode %p fail\n", vp);
	ext2fs_htree_release(info);
	return (-1);
}

/* 
 * Check if next leaf directory block contains the target entry.
 */
static int
ext2fs_htree_check_next(struct vnode *vp, uint32_t hash, const char *name,
			struct ext2fs_htree_lookup_info *info)
{
	struct ext2fs_htree_lookup_level *level;
	struct buf *bp;
	uint32_t next_hash;
	int idx = info->h_levels_num - 1;
	int levels = 0;
// 	printf("ext2fs_htree_check_next %s\n", name);

	do {
		level = &info->h_levels[idx];
		level->h_entry++;
		if (level->h_entry < level->h_entries +
			ext2fs_htree_get_count(level->h_entries)) {
// 			printf("level %d, ok\n", idx);
			break;
		}
// 		printf("level %d, full\n", idx);
		if (idx == 0) {
// 			printf("level %d, out of nodes\n", idx);
			return (0);
		}
		idx--;
		levels++;
	} while (1);

	next_hash = ext2fs_htree_get_hash(level->h_entry);
	if ((hash & 1) == 0) {
		if (hash != (next_hash & ~1)) {
// 			printf("cond 0x%8X 0x%8X\n", hash, next_hash);
			return (0);
		}
	}

	while (levels > 0) {
		levels--;
		if (ext2fs_blkatoff(vp, ext2fs_htree_get_block(level->h_entry) *
			VTOI(vp)->i_e2fs->e2fs_bsize, NULL, &bp) != 0)
			return (0);
		level = &info->h_levels[idx + 1];
		brelse(level->h_bp, 0);
		level->h_bp = bp;
		level->h_entry = level->h_entries =
			((struct ext2fs_htree_node *) bp->b_data)->h_entries;
	}
// 	printf("must check\n");

	return (1);
}

/*
 * Perform an entry lookup using HTree index.
 */
int
ext2fs_htree_lookup(struct vnode *vp, const char *name, int namelen,
		doff_t *offp, doff_t *prevoffp, doff_t *endusefulp,
		struct buf **bpp, struct ext2fs_searchslot *ss,
		struct ufs_lookup_results *results)
{
	struct ext2fs_htree_lookup_info info;
	struct ext2fs_htree_entry *leaf_node;
// 	struct ext2fs_direct *ep, *top;
	struct m_ext2fs *m_fs;
	struct buf *bp;
// 	doff_t entryoffset = 0;
// 	doff_t prevoffset = 0;
	uint32_t blknum;
	uint32_t dirhash;
	uint8_t hash_version;
	int search_next;
	int found = 0;

	m_fs = VTOI(vp)->i_e2fs;

	/* Force ext2fs_lookup to perform linear search for dot entries. */
	if ((namelen <= 2) && (name[0] == '.') &&
	    (name[1] == '.' || name[1] == 0))
		return (EXT2_HTREE_LOOKUP_ERROR);

	memset(&info, 0, sizeof(info));
	if (ext2fs_htree_find_leaf(vp, name, namelen, &dirhash,
		&hash_version, &info))
		return (EXT2_HTREE_LOOKUP_ERROR);

// 	printf("ext2fs_htree_lookup %s %d\n", name, namelen);
// 	printf("lookup: found %d levels\n", info.h_levels_num);
// 	int i;
// 	for (i = 0; i < info.h_levels_num; i++)
// 		printf("%d: buf %p, ent %p, at %p, off %ld\n", i,
// 			info.h_levels[i].h_bp,
// 			info.h_levels[i].h_entries,
// 			info.h_levels[i].h_entry,
// 			info.h_levels[i].h_entry - info.h_levels[i].h_entries);
// 	printf("OK\n");

	do {
		leaf_node = info.h_levels[info.h_levels_num - 1].h_entry;
		blknum = ext2fs_htree_get_block(leaf_node);
		printf("look %u %u\n", blknum, blknum * m_fs->e2fs_bsize);
		if (ext2fs_blkatoff(vp, blknum * m_fs->e2fs_bsize,
			NULL, &bp) != 0) {
			printf("lookup: blkatoff error\n");
			ext2fs_htree_release(&info);
			return (EXT2_HTREE_LOOKUP_ERROR);
		}

		// XXX what if ulr_offset != 0
		results->ulr_offset = blknum * m_fs->e2fs_bsize;
		/*
	// 	printf("ok, blk %u\n", blknum);
		ep = (struct ext2fs_direct *) bp->b_data;
		top = (struct ext2fs_direct *) ((char *) ep +
			m_fs->e2fs_bsize - EXT2FS_DIRSIZ(0));

		while (ep < top) {
			if (fs2h32(ep->e2d_ino) != 0 &&
				namelen == ep->e2d_namlen &&
				!memcmp(name, ep->e2d_name,
					(unsigned) namelen)) {
				*offp = entryoffset;
				*prevoffp = prevoffset;
				*bpp = bp;
				ext2fs_htree_release(&info);
				return (EXT2_HTREE_LOOKUP_FOUND);
			}
			prevoffset = entryoffset;
			entryoffset += fs2h16(ep->e2d_reclen);
			ep = (struct ext2fs_direct *)
				((char *) bp->b_data + entryoffset);
		}
		*/
		*offp = 0;
		*prevoffp = results->ulr_offset;
		*endusefulp = results->ulr_offset;
		if (ss->slotstatus == NONE) {
			ss->slotoffset = -1;
			ss->slotfreespace = 0;
		}

// 		printf("results: %d %d %d %d %d\n", results->ulr_count, results->ulr_endoff,
// 		       results->ulr_diroff, results->ulr_offset, results->ulr_reclen);
		if (ext2fs_search_dirblock(vp, bp->b_data, &found,
		       name, namelen, offp, prevoffp, endusefulp,
		       ss, results) != 0) {
			brelse(bp, 0);
			ext2fs_htree_release(&info);
			return (EXT2_HTREE_LOOKUP_ERROR);
		}

		if (found) {
			printf("idx found: %s %d %d %d\n", name, *offp, *prevoffp, *endusefulp);
			*bpp = bp;
			ext2fs_htree_release(&info);
			return (EXT2_HTREE_LOOKUP_FOUND);
		}

		brelse(bp, 0);
		search_next = ext2fs_htree_check_next(vp, dirhash, name, &info);
// 		if (search_next)
// 			printf("%s next!\n", name);
	} while (search_next);

	ext2fs_htree_release(&info);
	return (EXT2_HTREE_LOOKUP_NOT_FOUND);
}

/*
 * Compare two entry sort descriptors by name hash value.
 * This is used together with kheapsort().
 */
static int
ext2fs_htree_cmp_sort_entry(const void *e1, const void *e2)
{
	const struct ext2fs_htree_sort_entry *entry1, *entry2;
	entry1 = (const struct ext2fs_htree_sort_entry *) e1;
	entry2 = (const struct ext2fs_htree_sort_entry *) e2;

	if (entry1->h_hash < entry2->h_hash)
		return (-1);
	if (entry1->h_hash > entry2->h_hash)
		return (1);
	return (0);
}

/*
 * Append an entry to the end of the directory block.
 */
static void
ext2fs_append_entry(char *block, uint32_t blksize,
		    struct ext2fs_direct *last_entry,
		    struct ext2fs_direct *new_entry)
{
	uint16_t entry_len;

	char buf[150] = {0};
	memset(buf, 0, 150);
	memcpy(buf, last_entry->e2d_name, last_entry->e2d_namlen);
	snprintf(buf + last_entry->e2d_namlen, 100, ": LAST ENTRY %u [%u]\n",
		 last_entry->e2d_reclen, last_entry->e2d_ino);
	printf("%s", buf);
	
	entry_len = EXT2FS_DIRSIZ(last_entry->e2d_namlen);
	last_entry->e2d_reclen = h2fs16(entry_len);
	
	printf("new reclen %u\n", last_entry->e2d_reclen);
	printf("adding entry %u %u\n", new_entry->e2d_reclen, new_entry->e2d_ino);
	
	last_entry = (struct ext2fs_direct *) ((char *) last_entry + entry_len);
	entry_len = EXT2FS_DIRSIZ(new_entry->e2d_namlen);
	new_entry->e2d_reclen = h2fs16(block + blksize - (char *) last_entry);
	
	printf("new entry reclen %u\n", new_entry->e2d_reclen);
	
	memcpy(last_entry, new_entry, entry_len);
}

/*
 * Move half of entries from the old directory block to the new one.
 */
static int
ext2fs_htree_split_dirblock(char *block1, char *block2, uint32_t blksize,
			    uint32_t *hash_seed, uint8_t hash_version,
			    uint32_t *split_hash, struct ext2fs_direct *entry)
{
	int entry_cnt = 0;
	int move_cnt = 0;
	int size = 0;
	int i, k;
	uint16_t entry_len = 0;
	uint32_t entry_hash;
	struct ext2fs_direct *ep, *last;
	struct ext2fs_direct *prev;
	char *dest;
	struct ext2fs_htree_sort_entry *sort_info, dummy;

	int moved = 0;

	ep = (struct ext2fs_direct *) block1;
	dest = block2;
	sort_info = (struct ext2fs_htree_sort_entry *)
		((char *) block2 + blksize);

	/* Calculate name hash for the entry which is to be added. */
	ext2fs_htree_hash(entry->e2d_name, entry->e2d_namlen, hash_seed,
			  hash_version, &entry_hash, NULL);

	printf("hash 0x%08X\n", entry_hash);
	/* Fill in directory entry sort descriptors. */
	while ((char *) ep < block1 + blksize) {
		if (fs2h32(ep->e2d_ino) != 0 && ep->e2d_namlen != 0) {
			entry_cnt++;
			sort_info--;
			sort_info->h_size = fs2h16(ep->e2d_reclen);
			sort_info->h_offset = (char *) ep - block1;
			ext2fs_htree_hash(ep->e2d_name, ep->e2d_namlen,
					hash_seed, hash_version,
					&sort_info->h_hash, NULL);
		}
		ep = (struct ext2fs_direct *)
			((char *) ep + fs2h16(ep->e2d_reclen));
	}
	printf("filled\n");

	/* Sort directory entry descriptors by name hash value. */
	kheapsort(sort_info, entry_cnt, sizeof(struct ext2fs_htree_sort_entry),
		  ext2fs_htree_cmp_sort_entry, &dummy);
	printf("sorted\n");
	/* Count the number of entries to move to directory block 2. */
	for (i = entry_cnt - 1; i >= 0; i--) {
		if (sort_info[i].h_size + size > blksize / 2)
			break;
		size += sort_info[i].h_size;
		move_cnt++;
	}

	printf("split at %d\n", i + 1);
	*split_hash = sort_info[i + 1].h_hash;
	/* Set collision bit. */
	if (*split_hash == sort_info[i].h_hash) {
		printf("collision\n");
		*split_hash += 1;
	}
	
	printf("%d entries:\n", entry_cnt);
	ep = (struct ext2fs_direct *) ((char *) block1);
	for (k = 0; k < entry_cnt; k++) {
		char buf[150] = {0};
		memset(buf, 0, 150);
		memcpy(buf, ep->e2d_name, ep->e2d_namlen);
		snprintf(buf + ep->e2d_namlen, 100, ": %d %u [%u]\n", k, ep->e2d_reclen, ep->e2d_ino);
		printf("%s", buf);
		if (ep->e2d_reclen == 0)
		{
			printf("RECLEN = 0\n");
			break;
		}
// 		if (ep->e2d_ino == 0)
// 		{
// 			printf("INO = 0\n");
// 			break;
// 		}
		if (k > 2000) {
			printf("OVERFLOW\n");
			break;
		}
		ep = (struct ext2fs_direct *) ((char *) ep + ep->e2d_reclen);
	}
	
	printf("\nagain in hash order:\n");
	for (k = 0; k < entry_cnt; k++) {
		ep = (struct ext2fs_direct *) ((char *) block1 +
			sort_info[k].h_offset);
		char buf[100] = {0};
		snprintf(buf, 98, "%d: %u [%u] %s\n", k, ep->e2d_reclen, ep->e2d_ino, ep->e2d_name);
		printf("%s", buf);
		if (k > 2000) {
			printf("OVERFLOW\n");
			break;
		}
	}

	printf("\nmoving:\n");
	/* Move half of directory entries from block 1 to block 2. */
	for (k = i + 1; k < entry_cnt; k++) {
		ep = (struct ext2fs_direct *) ((char *) block1 +
			sort_info[k].h_offset);
		entry_len = EXT2FS_DIRSIZ(ep->e2d_namlen);
		memcpy(dest, ep, entry_len);
		((struct ext2fs_direct *) dest)->e2d_reclen = h2fs16(entry_len);
		printf("%d moved %s %u [%u]\n", k,
		       ((struct ext2fs_direct *) dest)->e2d_name,
		       ((struct ext2fs_direct *) dest)->e2d_reclen,
			((struct ext2fs_direct *) dest)->e2d_ino);
		/* Mark directory entry as unused. */
		ep->e2d_ino = 0;
		dest += entry_len;



		moved++;
	}
	dest -= entry_len;

	printf("\nfirst block:\n");
	ep = (struct ext2fs_direct *) block1;

	last = ep;
	k=0;
	while ((char*)ep < (block1 + blksize)) {
		char buf[150] = {0};
		memset(buf, 0, 150);
		memcpy(buf, ep->e2d_name, ep->e2d_namlen);
		snprintf(buf + ep->e2d_namlen, 100, ": %d %u [%u]\n", k, ep->e2d_reclen, ep->e2d_ino);
		printf("%s", buf);
		k++;
		
		last = ep;
		
		ep = (struct ext2fs_direct *) ((char *) ep + ep->e2d_reclen);
		if (k > 2000) {
			printf("OVERFLOW\n");
			break;
		}
	}
	
	printf("\nsecond block:\n");
	ep = (struct ext2fs_direct *) block2;
	k=0;
// 	while ((char*)ep < (block2 + blksize)) {
	for (k = 0; k < moved; k++) {
		char buf[150] = {0};
		memset(buf, 0, 150);
		memcpy(buf, ep->e2d_name, ep->e2d_namlen);
		snprintf(buf + ep->e2d_namlen, 100, ": %d %u [%u]\n", k, ep->e2d_reclen, ep->e2d_ino);
		printf("%s", buf);
// 		k++;
		
		
		
		
		
		
		
		if (k > 2000) {
			printf("OVERFLOW\n");
			break;
		}
		
		ep = (struct ext2fs_direct *) ((char *) ep + ep->e2d_reclen);
	}

	// XXX bug here
	/* Shrink directory entries in block 1. */
	prev = last = ep = (struct ext2fs_direct *) block1;
	while ((char *) ep < block1 + blksize) {
		if (fs2h32(ep->e2d_ino) != 0 && ep->e2d_namlen != 0) {
			entry_len = EXT2FS_DIRSIZ(ep->e2d_namlen);
			if (ep > prev)
				memmove(prev, ep, entry_len);
			prev->e2d_reclen = h2fs16(entry_len);
			last = prev;
			prev = (struct ext2fs_direct*)((char*)prev + entry_len);
		}
		ep = (struct ext2fs_direct *)
			((char *) ep + fs2h16(ep->e2d_reclen));
	}

// 	printf("\nshrinked block:\n");
// 	ep = (struct ext2fs_direct *) block1;
// 	k=0;
// 	while ((char*)ep < (block1 + blksize)) {
// 		char buf[150] = {0};
// 		memset(buf, 0, 150);
// 		memcpy(buf, ep->e2d_name, ep->e2d_namlen);
// 		snprintf(buf + ep->e2d_namlen, 100, ": %d %u [%u]\n", k, ep->e2d_reclen, ep->e2d_ino);
// 		printf("%s", buf);
// 		k++;
// 		
// 		
// // 		last = ep;
// 		
// 		
// 		ep = (struct ext2fs_direct *) ((char *) ep + ep->e2d_reclen);
// 	}

	if (entry_hash >= *split_hash) {
		printf("append %s %u %u to block2\n", entry->e2d_name, entry->e2d_reclen, entry->e2d_ino);
		/* Add entry to block 2. */
		ext2fs_append_entry(block2, blksize,
				    (struct ext2fs_direct *) dest, entry);
		
// 		ep = (struct ext2fs_direct *) block2;
// 		while ((char*)ep < (block2 + blksize)) {
// 			char buf[100] = {0};
// 			snprintf(buf, 98, "%05u [%08u] %s\n", ep->e2d_reclen, ep->e2d_ino, ep->e2d_name);
// 			printf("%s\n", buf);
// 			ep = (struct ext2fs_direct *) ((char *) ep + ep->e2d_reclen);
// 		}

		printf("last %s %u %u\n", last->e2d_name, last->e2d_reclen, last->e2d_ino);
		/* Adjust length field in last entry of block 1. */
		last->e2d_reclen = h2fs16(block1 + blksize - (char *) last);
		printf("last became %u\n", last->e2d_reclen);
		
	} else {
		printf("append %s %u %u to block1\n", entry->e2d_name, entry->e2d_reclen, entry->e2d_ino);
		
		/* Add entry to block 1. */
		ext2fs_append_entry(block1, blksize, last, entry);

// 		ep = (struct ext2fs_direct *) block1;
// 		while ((char*)ep < (block1 + blksize)) {
// 			char buf[100] = {0};
// 			snprintf(buf, 98, "%05u [%08u] %s\n", ep->e2d_reclen, ep->e2d_ino, ep->e2d_name);
// 			printf("%s\n", buf);
// 			ep = (struct ext2fs_direct *) ((char *) ep + ep->e2d_reclen);
// 		}
		
		printf("last %s %u %u\n", ((struct ext2fs_direct *) dest)->e2d_name,
			((struct ext2fs_direct *) dest)->e2d_reclen,
		       ((struct ext2fs_direct *) dest)->e2d_ino);
		
		/* Adjust length field in last entry of block 2. */
		((struct ext2fs_direct *) dest)->e2d_reclen = h2fs16(block2 +
								blksize - dest);
		
		printf("last became %u\n", ((struct ext2fs_direct *) dest)->e2d_reclen);
	}

	return (0);
}

/*
 * Create an HTree index for the directory.
 */
int
ext2fs_htree_create_index(struct vnode *vp, struct componentname *cnp,
			  struct ext2fs_direct *new_entry)
{
	struct buf *bp = NULL;
	struct inode *dp;
	struct ext2fs *fs;
	struct m_ext2fs *m_fs;
	struct ext2fs_direct *ep, *dotdot;
	struct ext2fs_htree_root *root;
	struct ext2fs_htree_lookup_info info;
	struct iovec aiov;
	struct uio auio;
	uint32_t blksize, dirlen, split_hash;
	uint8_t hash_version;
	char *buf1 = NULL;
	char *buf2 = NULL;
	int error = 0;

	fs = &(VTOI(vp)->i_e2fs->e2fs);
	m_fs = VTOI(vp)->i_e2fs;
	dp = VTOI(vp);
	blksize = m_fs->e2fs_bsize;

	buf1 = kmem_zalloc(blksize, KM_SLEEP);
	buf2 = kmem_zalloc(blksize, KM_SLEEP);

	if ((error = ext2fs_blkatoff(vp, 0, NULL, &bp)) != 0)
		goto create_index_finish;

	root = (struct ext2fs_htree_root *) bp->b_data;
	dotdot = (struct ext2fs_direct* )
		((char* ) &(root->h_header.dotdot_ino));
	ep = (struct ext2fs_direct* ) ((char *) dotdot + dotdot->e2d_reclen);
	dirlen = (char *) root + blksize - (char *) ep;
	memcpy(buf1, ep, dirlen);
	ep = (struct ext2fs_direct *) buf1;
	while ((char *) ep < buf1 + dirlen)
		ep = (struct ext2fs_direct *)
			((char *) ep + fs2h16(ep->e2d_reclen));
	ep->e2d_reclen = h2fs16(buf1 + blksize - (char *) ep);

// 	printf("len %u\n", dirlen);
// 	printf("dotdot: %u %u %u %u %s\n", dotdot->e2d_ino, dotdot->e2d_reclen,
// 	       dotdot->e2d_type, dotdot->e2d_namlen, dotdot->e2d_name);
// 	printf("ep: %u %u %u %u %s\n", ep->e2d_ino, ep->e2d_reclen,
// 	       ep->e2d_type, ep->e2d_namlen, ep->e2d_name);

	VTOI(vp)->i_e2fs_flags |= EXT2_HTREE;

	/* Initialize index root. */
	dotdot->e2d_reclen = h2fs16(blksize - EXT2FS_DIRSIZ(2));
// 	printf("dotdot len %u\n", dotdot->e2d_reclen);
	memset(&root->h_info, 0, sizeof(root->h_info));
	root->h_info.h_hash_version = fs->e2fs_def_hash_version;
	root->h_info.h_info_len = sizeof(root->h_info);
// 	printf("hash ver %u, len %u\n", root->h_info.h_hash_version,
// 	       root->h_info.h_info_len);
	ext2fs_htree_set_block(root->h_entries, 1);
	ext2fs_htree_set_count(root->h_entries, 1);
	ext2fs_htree_set_limit(root->h_entries,
			       ext2fs_htree_root_limit(VTOI(vp),
						       sizeof(root->h_info)));

	memset(&info, 0, sizeof(info));
	info.h_levels_num = 1;
	info.h_levels[0].h_entries = root->h_entries;
	info.h_levels[0].h_entry = root->h_entries;

	hash_version = root->h_info.h_hash_version;
	if (hash_version <= EXT2_HTREE_TEA)
		hash_version += m_fs->e2fs_uhash;
	ext2fs_htree_split_dirblock(buf1, buf2, blksize, fs->e2fs_hash_seed,
				    hash_version, &split_hash, new_entry);
// 	printf("split hash 0x%X\n", split_hash);
	ext2fs_htree_insert_entry(&info, split_hash, 2);

	/* Write directory block 0. */
	error = VOP_BWRITE(bp->b_vp, bp);
	dp->i_flag |= IN_CHANGE | IN_UPDATE;
	printf("wrote block 0\n");

	/* Write directory block 1. */
	auio.uio_offset = blksize;
	auio.uio_resid = blksize;
	aiov.iov_len = blksize;
	aiov.iov_base = buf1;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_rw = UIO_WRITE;
	UIO_SETUP_SYSSPACE(&auio);
	error = VOP_WRITE(vp, &auio, IO_SYNC, cnp->cn_cred);
	if (!error) {
		error = ext2fs_setsize(dp, roundup(ext2fs_size(dp), blksize));
		if (error)
			goto create_index_finish;
		uvm_vnp_setsize(vp, ext2fs_size(dp));
		printf("wrote block 1\n");
	}
	
	/* Write directory block 2. */
	auio.uio_offset = blksize * 2;
	auio.uio_resid = blksize;
	aiov.iov_len = blksize;
	aiov.iov_base = buf2;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_rw = UIO_WRITE;
	UIO_SETUP_SYSSPACE(&auio);
	error = VOP_WRITE(vp, &auio, IO_SYNC, cnp->cn_cred);
	if (!error) {
		error = ext2fs_setsize(dp, roundup(ext2fs_size(dp), blksize));
		if (error)
			goto create_index_finish;
		uvm_vnp_setsize(vp, ext2fs_size(dp));
		printf("wrote block 2\n");
	}

create_index_finish:
	if (bp != NULL)
		brelse(bp, 0);
	kmem_free(buf1, blksize);
	kmem_free(buf2, blksize);
	if (error)
		return (-1);
	else
		return (0);
}

/*
 * Add an entry to the directory using HTree index.
 */
int
ext2fs_htree_add_entry(struct vnode *dvp, const struct ufs_lookup_results *ulr,
		       struct ext2fs_direct *entry, struct componentname *cnp)
{
	struct ext2fs_htree_entry *entries, *leaf_node;
	struct ext2fs_htree_lookup_info info;
	struct buf *bp;
	struct ext2fs *fs;
	struct m_ext2fs *m_fs;
	struct inode *ip;
	struct iovec aiov;
	struct uio auio;
	uint32_t dirhash, split_hash;
	uint32_t blksize, blknum;
	uint64_t cursize, dirsize;
	uint8_t hash_version;
	char *newblock = NULL;
	int error;

	ip = VTOI(dvp);
	fs = &(ip->i_e2fs->e2fs);
	m_fs = ip->i_e2fs;
	blksize = m_fs->e2fs_bsize;

	printf("add at offset %u\n", ulr->ulr_offset);
	if (ulr->ulr_count != 0) {
		printf("idx add cnt %s %u\n", entry->e2d_name, ulr->ulr_count);
		return ext2fs_add_entry(dvp, ulr, entry);
	}
	printf("idx add no space\n");

	memset(&info, 0, sizeof(info));
	if (ext2fs_htree_find_leaf(dvp, entry->e2d_name, entry->e2d_namlen,
			       &dirhash, &hash_version, &info))
		return -1;
	printf("found at hash 0x%08X, ver %u\n", dirhash, hash_version);
	entries = info.h_levels[info.h_levels_num - 1].h_entries;
	if (ext2fs_htree_get_count(entries) == ext2fs_htree_get_limit(entries)) {
		printf("ENTRIES LIMIT %u\n", ext2fs_htree_get_count(entries));
		ext2fs_htree_release(&info);
		return -1;
	}

	leaf_node = info.h_levels[info.h_levels_num - 1].h_entry;
	blknum = ext2fs_htree_get_block(leaf_node);
	printf("look %u %u\n", blknum, blknum * blksize);
	if ((error = ext2fs_blkatoff(dvp, blknum * blksize,
		NULL, &bp)) != 0) {
		printf("lookup: blkatoff error\n");
		return -1; // XXX
	}

	newblock = kmem_zalloc(blksize, KM_SLEEP);
	printf("will split\n");
	ext2fs_htree_split_dirblock((char* ) bp->b_data, newblock, blksize,
				    fs->e2fs_hash_seed, hash_version,
				    &split_hash, entry);
	cursize = roundup(ext2fs_size(ip), blksize);
	dirsize = roundup(ext2fs_size(ip), blksize) + blksize;
	blknum = dirsize / blksize - 1;
	printf("split ok, cursize %ld, newsize %ld, blknum %u\n",
	       cursize, dirsize, blknum);
	ext2fs_htree_insert_entry(&info, split_hash, blknum);

	auio.uio_offset = cursize;
	auio.uio_resid = blksize;
	aiov.iov_len = blksize;
	aiov.iov_base = newblock;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_rw = UIO_WRITE;
	UIO_SETUP_SYSSPACE(&auio);
	error = VOP_WRITE(dvp, &auio, IO_SYNC, cnp->cn_cred);
	if (!error) {
		error = ext2fs_setsize(ip, dirsize);
		if (error)
			// XXX proper 
			return -1;
		uvm_vnp_setsize(dvp, ext2fs_size(ip));
		printf("wrote new block\n");
	}

	error = VOP_BWRITE(bp->b_vp, bp);
	ip->i_flag |= IN_CHANGE | IN_UPDATE;
	printf("wrote orig block\n");

	error = ext2fs_htree_writebuf(&info);
	if (error) {
		// XXX proper
		printf("error saving\n");
		return -1;
	}

	ext2fs_htree_release(&info);
	if (bp != NULL)
		brelse(bp, 0);
	kmem_free(newblock, blksize);

	/* There is no space in target directory block, split it. */
	printf("idx add no space OK\n");
	return (0);
}

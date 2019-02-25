/*
 * This file is part of the Motsognir gopher server
 * Copyright (C) 2008-2019 Mateusz Viste
 *
 * Provides a simple db-like system for storing and mapping file extensions
 */

#ifndef extmap_h_sentinel
#define extmap_h_sentinel

struct extmap_t;

/* loads a extension->filetype mapping file, or loads a default map if file is NULL */
struct extmap_t *extmap_load(const char *file);

/* frees the memory allocated to an extmap */
void extmap_free(struct extmap_t *obj);

/* performs a lookup of an extension in our mapping system, and return the gopher type char */
char extmap_lookup(const struct extmap_t *obj, const char *extension);

#endif

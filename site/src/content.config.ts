import { defineCollection } from 'astro:content';
import { glob } from 'astro/loaders';
import { DOC_FILES, POLICY_DIR } from './lib/docs';

const docs = defineCollection({
  loader: glob({
    base: '..',
    pattern: [...DOC_FILES, `${POLICY_DIR}/*.md`],
    generateId: ({ entry }) => entry.replace(/\.md$/, ''),
  }),
});

export const collections = { docs };

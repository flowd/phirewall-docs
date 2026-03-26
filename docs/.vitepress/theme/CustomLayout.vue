<script setup>
import DefaultTheme from 'vitepress/theme'
import ServicesBanner from './ServicesBanner.vue'
import { useData } from 'vitepress'

const { Layout } = DefaultTheme
const { frontmatter } = useData()
</script>

<template>
  <Layout>
    <template #doc-after>
      <ServicesBanner v-if="frontmatter.layout !== 'home'" />
    </template>
  </Layout>
</template>

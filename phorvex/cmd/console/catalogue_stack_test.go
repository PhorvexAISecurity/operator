package main

import (
	"testing"

	"github.com/phorvex/phorvex/internal/console"
)

func TestStackCatalogueDeploymentEnvironmentMapsPinnedAuthority(t *testing.T) {
	values := map[string]string{
		"PHORVEX_CONSOLE_CATALOGUE_V1_ENABLED":                   "true",
		"PHORVEX_CONSOLE_CATALOGUE_CHROMA_ENABLED":               "true",
		"PHORVEX_CONSOLE_CATALOGUE_CHROMA_NAMESPACE":             "document-store",
		"PHORVEX_CONSOLE_CATALOGUE_CHROMA_DEPLOYMENT":            "chroma",
		"PHORVEX_CONSOLE_CATALOGUE_CHROMA_SERVICE":               "chroma",
		"PHORVEX_CONSOLE_CATALOGUE_CHROMA_CONTAINER":             "chroma",
		"PHORVEX_CONSOLE_CATALOGUE_CHROMA_PORT":                  "8000",
		"PHORVEX_CONSOLE_CATALOGUE_CHROMA_IMAGE_ID":              "image-pin",
		"PHORVEX_CONSOLE_CATALOGUE_CHROMA_VERSION_SOURCE_SHA256": "version-pin",
		"PHORVEX_CONSOLE_CATALOGUE_CHROMA_SERVER_SOURCE_SHA256":  "server-pin",
		"PHORVEX_CONSOLE_CATALOGUE_CHROMA_SCHEMA_SOURCE_SHA256":  "schema-pin",
		"PHORVEX_CONSOLE_CATALOGUE_LITELLM_ENABLED":              "true",
		"PHORVEX_CONSOLE_CATALOGUE_LITELLM_NAMESPACE":            "litellm",
		"PHORVEX_CONSOLE_CATALOGUE_LITELLM_DEPLOYMENT":           "litellm",
		"PHORVEX_CONSOLE_CATALOGUE_LITELLM_SERVICE":              "litellm",
		"PHORVEX_CONSOLE_CATALOGUE_LITELLM_CONTAINER":            "litellm",
		"PHORVEX_CONSOLE_CATALOGUE_LITELLM_PORT":                 "4000",
		"PHORVEX_CONSOLE_CATALOGUE_LITELLM_CONFIGMAP":            "litellm-config",
		"PHORVEX_CONSOLE_CATALOGUE_LITELLM_CONFIG_KEY":           "config.yaml",
		"PHORVEX_CONSOLE_CATALOGUE_LITELLM_CONFIG_SHA256":        "config-pin",
	}
	lookup := func(key string) (string, bool) { value, ok := values[key]; return value, ok }
	var cfg console.Config
	if err := applyCatalogueV1Environment(&cfg, lookup); err != nil {
		t.Fatal(err)
	}
	c := cfg.CatalogueV1
	if !c.Enabled || !c.ChromaEnabled || !c.LiteLLMEnabled || c.ChromaPort != 8000 || c.LiteLLMPort != 4000 ||
		c.ChromaNamespace != "document-store" || c.ChromaImageID != "image-pin" || c.ChromaSchemaSourceSHA256 != "schema-pin" ||
		c.LiteLLMNamespace != "litellm" || c.LiteLLMConfigMap != "litellm-config" || c.LiteLLMConfigSHA256 != "config-pin" {
		t.Fatalf("stack runtime environment lost authority: %+v", c)
	}
	values["PHORVEX_CONSOLE_CATALOGUE_LITELLM_PORT"] = "04000"
	if err := applyCatalogueV1Environment(&cfg, lookup); err == nil {
		t.Fatal("noncanonical LiteLLM port was accepted")
	}
}

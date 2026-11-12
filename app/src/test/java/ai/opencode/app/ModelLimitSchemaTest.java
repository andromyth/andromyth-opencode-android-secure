package ai.opencode.app;

import org.junit.Test;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/** Regression tests for the OpenCode model limit schema. */
public class ModelLimitSchemaTest {

    @Test public void contextOverride_isNotWrittenWithoutOutputLimit() {
        Map<String, Object> model = new LinkedHashMap<>();
        model.put("name", "DeepSeek V4.1 Flash Free");
        Map<String, Object> models = new LinkedHashMap<>();
        models.put("deepseek-v4.1-flash-free", model);
        Map<String, Object> provider = new LinkedHashMap<>();
        provider.put("models", models);
        Map<String, Object> providers = new LinkedHashMap<>();
        providers.put("opencode", provider);
        Map<String, Object> root = new LinkedHashMap<>();
        root.put("provider", providers);

        assertFalse(ContextPolicy.mergeContextLimit(
                root, "opencode", "deepseek-v4.1-flash-free", 200_000));
        assertFalse(model.containsKey("limit"));
    }

    @Test public void sanitizerRemovesPreviouslyWrittenContextOnlyLimit() {
        Map<String, Object> limit = new LinkedHashMap<>();
        limit.put("context", 200_000L);
        Map<String, Object> model = new LinkedHashMap<>();
        model.put("limit", limit);
        Map<String, Object> models = new LinkedHashMap<>();
        models.put("deepseek-v4.1-flash-free", model);
        Map<String, Object> provider = new LinkedHashMap<>();
        provider.put("models", models);
        Map<String, Object> providers = new LinkedHashMap<>();
        providers.put("opencode", provider);
        Map<String, Object> root = new LinkedHashMap<>();
        root.put("provider", providers);

        assertTrue(ContextPolicy.sanitizeConfig(root));
        assertFalse(model.containsKey("limit"));
        assertFalse(ContextPolicy.sanitizeConfig(root));
    }

    @Test public void validOutputLimitPreservesContextOverride() {
        Map<String, Object> limit = new LinkedHashMap<>();
        limit.put("context", 200_000L);
        limit.put("output", 16_384L);
        Map<String, Object> model = new LinkedHashMap<>();
        model.put("limit", limit);
        Map<String, Object> models = new LinkedHashMap<>();
        models.put("deepseek-model", model);
        Map<String, Object> provider = new LinkedHashMap<>();
        provider.put("models", models);
        Map<String, Object> providers = new LinkedHashMap<>();
        providers.put("test-provider", provider);
        Map<String, Object> root = new LinkedHashMap<>();
        root.put("provider", providers);

        assertFalse(ContextPolicy.sanitizeConfig(root));
        assertTrue(ContextPolicy.mergeContextLimit(
                root, "test-provider", "deepseek-model", 128_000));
    }
}

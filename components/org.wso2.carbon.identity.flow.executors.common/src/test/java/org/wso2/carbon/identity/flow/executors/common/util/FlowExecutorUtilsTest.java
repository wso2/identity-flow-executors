/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.flow.executors.common.util;

import org.testng.annotations.Test;
import org.wso2.carbon.identity.flow.execution.engine.model.ExecutorResponse;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionContext;
import org.wso2.carbon.identity.flow.mgt.model.ExecutorDTO;
import org.wso2.carbon.identity.flow.mgt.model.NodeConfig;

import java.util.Arrays;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_CLIENT_INPUT_REQUIRED;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_ERROR;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_USER_ERROR;

/**
 * Unit tests for {@link FlowExecutorUtils}.
 */
public class FlowExecutorUtilsTest {

    private static final String EXECUTOR_NAME = "TestExecutor";
    private static final String METADATA_KEY = "key";

    @Test
    public void testGetMetadataValue() {

        ExecutorDTO executorDTO = new ExecutorDTO(EXECUTOR_NAME);
        executorDTO.addMetadata(METADATA_KEY, "value");
        FlowExecutionContext context = buildContext(executorDTO);

        assertEquals(FlowExecutorUtils.getMetadataValue(context, METADATA_KEY), "value");
        assertNull(FlowExecutorUtils.getMetadataValue(context, "other"));
    }

    @Test
    public void testGetMetadataValueWithoutMetadata() {

        assertNull(FlowExecutorUtils.getMetadataValue(new FlowExecutionContext(), METADATA_KEY));
        assertNull(FlowExecutorUtils.getMetadataValue(buildContext(null), METADATA_KEY));
        assertNull(FlowExecutorUtils.getMetadataValue(buildContext(new ExecutorDTO(EXECUTOR_NAME)), METADATA_KEY));
    }

    @Test
    public void testUserErrorResponse() {

        ExecutorResponse response = FlowExecutorUtils.userErrorResponse(new ExecutorResponse(), "Message.");

        assertEquals(response.getResult(), STATUS_USER_ERROR);
        assertEquals(response.getErrorMessage(), "Message.");
    }

    @Test
    public void testServerErrorResponse() {

        ExecutorResponse response = FlowExecutorUtils.serverErrorResponse(new ExecutorResponse(), "Message.");

        assertEquals(response.getResult(), STATUS_ERROR);
        assertEquals(response.getErrorMessage(), "Message.");
    }

    @Test
    public void testClientInputRequiredResponse() {

        ExecutorResponse response = FlowExecutorUtils.clientInputRequiredResponse(new ExecutorResponse(), "a", "b");

        assertEquals(response.getResult(), STATUS_CLIENT_INPUT_REQUIRED);
        assertEquals(response.getRequiredData(), Arrays.asList("a", "b"));
    }

    private FlowExecutionContext buildContext(ExecutorDTO executorDTO) {

        FlowExecutionContext context = new FlowExecutionContext();
        context.setCurrentNode(new NodeConfig.Builder().id("node").executorConfig(executorDTO).build());
        return context;
    }
}

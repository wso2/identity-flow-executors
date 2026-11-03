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

import org.wso2.carbon.identity.flow.execution.engine.model.ExecutorResponse;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionContext;
import org.wso2.carbon.identity.flow.mgt.model.ExecutorDTO;
import org.wso2.carbon.identity.flow.mgt.model.NodeConfig;

import java.util.Arrays;
import java.util.Map;

import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_CLIENT_INPUT_REQUIRED;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_ERROR;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_USER_ERROR;

/**
 * Utilities for the flow executors.
 */
public final class FlowExecutorUtils {

    private FlowExecutorUtils() {

    }

    /**
     * Get a metadata value of the executor of the current node.
     *
     * @param context Flow execution context.
     * @param key     Metadata key.
     * @return Metadata value, or null if the current node has no such metadata.
     */
    public static String getMetadataValue(FlowExecutionContext context, String key) {

        NodeConfig currentNode = context.getCurrentNode();
        if (currentNode == null) {
            return null;
        }
        ExecutorDTO executorConfig = currentNode.getExecutorConfig();
        if (executorConfig == null) {
            return null;
        }
        Map<String, String> metadata = executorConfig.getMetadata();
        if (metadata == null || metadata.isEmpty()) {
            return null;
        }
        return metadata.get(key);
    }

    /**
     * Set the user error status and message on the executor response.
     *
     * @param response     Executor response.
     * @param errorMessage Error message.
     * @return Executor response.
     */
    public static ExecutorResponse userErrorResponse(ExecutorResponse response, String errorMessage) {

        response.setResult(STATUS_USER_ERROR);
        response.setErrorMessage(errorMessage);
        return response;
    }

    /**
     * Set the server error status and message on the executor response.
     *
     * @param response     Executor response.
     * @param errorMessage Error message.
     * @return Executor response.
     */
    public static ExecutorResponse serverErrorResponse(ExecutorResponse response, String errorMessage) {

        response.setResult(STATUS_ERROR);
        response.setErrorMessage(errorMessage);
        return response;
    }

    /**
     * Set the client input required status and the required fields on the executor response.
     *
     * @param response Executor response.
     * @param fields   Required fields.
     * @return Executor response.
     */
    public static ExecutorResponse clientInputRequiredResponse(ExecutorResponse response, String... fields) {

        response.setResult(STATUS_CLIENT_INPUT_REQUIRED);
        response.setRequiredData(Arrays.asList(fields));
        return response;
    }
}

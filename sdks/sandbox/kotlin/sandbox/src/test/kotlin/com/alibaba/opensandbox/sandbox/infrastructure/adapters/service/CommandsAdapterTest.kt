/*
 * Copyright 2025 Alibaba Group Holding Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.alibaba.opensandbox.sandbox.infrastructure.adapters.service

import com.alibaba.opensandbox.sandbox.HttpClientProvider
import com.alibaba.opensandbox.sandbox.config.ConnectionConfig
import com.alibaba.opensandbox.sandbox.domain.models.execd.executions.ExecutionHandlers
import com.alibaba.opensandbox.sandbox.domain.models.execd.executions.RunCommandRequest
import com.alibaba.opensandbox.sandbox.domain.models.sandboxes.SandboxEndpoint
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class CommandsAdapterTest {
    private lateinit var mockWebServer: MockWebServer
    private lateinit var commandsAdapter: CommandsAdapter
    private lateinit var httpClientProvider: HttpClientProvider

    @BeforeEach
    fun setUp() {
        mockWebServer = MockWebServer()
        mockWebServer.start()

        // We need to parse the port from MockWebServer to simulate the Execd endpoint
        val host = mockWebServer.hostName
        val port = mockWebServer.port
        val endpoint = SandboxEndpoint("$host:$port")

        val config =
            ConnectionConfig.builder()
                .domain("$host:$port")
                .protocol("http")
                .build()

        httpClientProvider = HttpClientProvider(config)
        commandsAdapter = CommandsAdapter(httpClientProvider, endpoint)
    }

    @AfterEach
    fun tearDown() {
        mockWebServer.shutdown()
        httpClientProvider.close()
    }

    @Test
    fun `run should stream events correctly`() {
        // SSE format: event nodes are JSON objects separated by newlines
        val event1 = """{"type":"stdout","text":"Hello","timestamp":1672531200000}"""
        val event2 = """{"type":"execution_complete","execution_time":100,"timestamp":1672531201000}"""

        val responseBody = "$event1\n$event2\n"

        mockWebServer.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setBody(responseBody),
        )

        val receivedOutput = StringBuilder()
        val latch = CountDownLatch(1)
        var executionTime = -1L

        val handlers =
            ExecutionHandlers.builder()
                .onStdout { msg -> receivedOutput.append(msg.text) }
                .onExecutionComplete { complete ->
                    executionTime = complete.executionTimeInMillis
                    latch.countDown()
                }
                .build()

        val request =
            RunCommandRequest.builder()
                .command("echo Hello")
                .uid(1000)
                .gid(1000)
                .env("APP_ENV", "test")
                .env("LOG_LEVEL", "debug")
                .handlers(handlers)
                .build()

        commandsAdapter.run(request)

        assertTrue(latch.await(2, TimeUnit.SECONDS), "Timed out waiting for completion event")
        assertEquals("Hello", receivedOutput.toString())
        assertEquals(100L, executionTime)

        val recordedRequest = mockWebServer.takeRequest()
        assertEquals("/command", recordedRequest.path)
        assertEquals("POST", recordedRequest.method)
        val requestBodyJson = Json.parseToJsonElement(recordedRequest.body.readUtf8()).jsonObject
        assertEquals("echo Hello", requestBodyJson["command"]?.jsonPrimitive?.content)
        assertEquals(1000, requestBodyJson["uid"]?.jsonPrimitive?.intOrNull)
        assertEquals(1000, requestBodyJson["gid"]?.jsonPrimitive?.intOrNull)
        val envs = requestBodyJson["envs"]?.jsonObject
        assertEquals("test", envs?.get("APP_ENV")?.jsonPrimitive?.content)
        assertEquals("debug", envs?.get("LOG_LEVEL")?.jsonPrimitive?.content)
        // Builder defaults background to false; request body always includes it
        assertEquals(false, requestBodyJson["background"]?.jsonPrimitive?.booleanOrNull)
    }

    @Test
    fun `run command builder should require uid when gid is provided`() {
        assertThrows<IllegalArgumentException> {
            RunCommandRequest.builder()
                .command("id")
                .gid(1000)
                .build()
        }
    }
}

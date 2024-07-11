/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth2.token.handler.clientauth.mutualtls.internal;

import org.mockito.Mock;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.mutualtls.MutualTLSClientAuthenticator;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.testng.Assert.assertEquals;

public class MutualTLSServiceComponentTest {


    @Mock
    BundleContext bundleContext;

    @Mock
    private ComponentContext context;

    @BeforeClass
    public void setUp() throws Exception {

        initMocks(this);
    }

    @Test
    public void testActivate() throws Exception {

        when(context.getBundleContext()).thenReturn(this.bundleContext);

        final String[] serviceName = new String[1];

        doAnswer(new Answer<Object>() {

            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {

                MutualTLSClientAuthenticator mutualTLSClientAuthenticator =
                        (MutualTLSClientAuthenticator) invocation.getArguments()[1];
                serviceName[0] = mutualTLSClientAuthenticator.getClass().getName();
                return null;
            }
        }).when(this.bundleContext).registerService(anyString(), any(MutualTLSClientAuthenticator.class), isNull());

        MutualTLSServiceComponent mutualTLSServiceComponent = new MutualTLSServiceComponent();
        mutualTLSServiceComponent.activate(context);

        assertEquals(MutualTLSClientAuthenticator.class.getName(), serviceName[0], "error");
    }

}

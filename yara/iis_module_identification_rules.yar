import "pe"

rule Native_IIS_Module {
    strings:
        $subscribed = "This module subscribed to event"
        $override = "but did not override the method in its"
        $module1 = "CHttpModule"
        $module2 = "CGlobalModule"

    condition:
        pe.exports("RegisterModule") and
        (
            for any export in pe.export_details : (
                export.name == "RegisterModule" and
                export.ordinal == 1
            )
            or
            any of them
        )
}

rule Managed_IIS_Module {
    strings:
        $module = "IHttpModule"
        $dispose = "Dispose"
        
        $method1 = "AcquireRequestState"
        $method2 = "AuthenticateRequest"
        $method3 = "AuthorizeRequest"
        $method4 = "BeginRequest"
        $method5 = "EndRequest"
        $method6 = "LogRequest"
        $method7 = "MapRequestHandler"
        $method8 = "PostAcquireRequestState"
        $method9 = "PostAuthenticateRequest"
        $method10 = "PostAuthorizeRequest"
        $method11 = "PostLogRequest"
        $method12 = "PostMapRequestHandler"
        $method13 = "PostReleaseRequestState"
        $method14 = "PostRequestHandlerExecute"
        $method15 = "PostResolveRequestCache"
        $method16 = "PostUpdateRequestCache"
        $method17 = "PreRequestHandlerExecute"
        $method18 = "PreSendRequestContent"
        $method19 = "PreSendRequestHeaders"
        $method20 = "ReleaseRequestState"
        $method21 = "RequestCompleted"
        $method22 = "ResolveRequestCache"
        $method23 = "UpdateRequestCache"
        
    condition:
        pe.is_dll() and 
        $module and 
        $dispose and
        any of ($method*)
}
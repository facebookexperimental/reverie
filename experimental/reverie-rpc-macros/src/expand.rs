/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use proc_macro2::TokenStream;
use quote::quote;
use quote::ToTokens;
use quote::TokenStreamExt;
use syn::spanned::Spanned;

use crate::Method;
use crate::Service;

impl ToTokens for Service {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        tokens.append_all(&[
            self.expand_trait(),
            self.expand_server(),
            self.expand_request_enum(),
            self.expand_response_enum(),
            self.expand_client(),
        ]);
    }
}

impl Service {
    /// Expands the trait that the server needs to implement.
    fn expand_trait(&self) -> TokenStream {
        let attrs = &self.attrs;
        let vis = &self.vis;
        let ident = &self.ident;
        let server_ident = &self.server_ident;

        let methods = self.methods.iter().map(
            |Method {
                 attrs,
                 ident,
                 args,
                 output,
                 ..
             }| {
                quote! {
                    #( #attrs )*
                    async fn #ident(&self, #( #args ),*) #output;
                }
            },
        );

        quote! {
            #( #attrs )*
            #[::reverie_rpc::async_trait::async_trait]
            #vis trait #ident: ::core::marker::Sync + Sized {
                #( #methods )*

                /// Returns a type that can be used to serve this service.
                fn serve(self) -> #server_ident<Self> {
                    #server_ident { service: self }
                }
            }
        }
    }

    /// Expands `struct ServeMyService`
    /// Expands `impl<S> Service for ServeMyService<S>`
    fn expand_server(&self) -> TokenStream {
        let vis = &self.vis;
        let ident = &self.ident;
        let request_ident = &self.request_ident;
        let response_ident = &self.response_ident;
        let server_ident = &self.server_ident;

        let service_requests = self.methods.iter().map(|method| {
            let attrs = &method.attrs;
            let ident = &method.ident;
            let camel_ident = &method.camel_ident;
            let arg_pats = method.args.iter().map(|pat_type| &pat_type.pat).collect::<Vec<_>>();

            if method.method_attrs.no_response {
                quote! {
                    #( #attrs )*
                    #[allow(unused_doc_comments)]
                    #request_ident::#camel_ident { #( #arg_pats ),* } => {
                        self.service.#ident(#( #arg_pats ),*).await;
                        None
                    },
                }
            } else {
                quote! {
                    #( #attrs )*
                    #[allow(unused_doc_comments)]
                    #request_ident::#camel_ident { #( #arg_pats ),* } => {
                        Some(#response_ident::#camel_ident(self.service.#ident(#( #arg_pats ),*).await))
                    },
                }
            }
        });

        let request_lifetime: Option<syn::Generics> = self
            .request_generics
            .as_ref()
            .map(|_| syn::parse_quote!(<'r>));

        // FIXME: Avoid requiring `Send` if possible.
        quote! {
            /// A helper for serving the service.
            #[derive(Clone)]
            #vis struct #server_ident<S> {
                service: S,
            }

            impl<S> #server_ident<S> {
                pub fn into_inner(self) -> S {
                    self.service
                }
            }

            impl<S> core::ops::Deref for #server_ident<S> {
                type Target = S;

                fn deref(&self) -> &Self::Target {
                    &self.service
                }
            }

            impl<S> core::ops::DerefMut for #server_ident<S> {
                fn deref_mut(&mut self) -> &mut Self::Target {
                    &mut self.service
                }
            }

            impl<S> ::reverie_rpc::Service for #server_ident<S>
            where
                S: #ident + Send,
            {
                type Request<'r> where S: 'r = #request_ident #request_lifetime;
                type Response = #response_ident;
                type Future<'a> where S: 'a = ::reverie_rpc::BoxFuture<'a, Option<Self::Response>>;

                fn call<'a>(
                    &'a self,
                    req: Self::Request<'a>,
                ) -> Self::Future<'a> {
                    Box::pin(async move {
                        match req {
                            #( #service_requests )*
                        }
                    })
                }
            }
        }
    }

    /// Expands the associated request type for each method's arguments.
    fn expand_request_enum(&self) -> TokenStream {
        let variants = self.methods.iter().map(|method| {
            let attrs = &method.attrs;
            let ident = &method.camel_ident;
            let args = method.args.iter().cloned().map(|mut arg| {
                // If we have an argument with a reference, change it to our
                // 'req lifetime that is declared on the enum.
                if let syn::Type::Reference(r) = arg.ty.as_mut() {
                    r.lifetime = Some(syn::Lifetime::new("'req", r.and_token.span()));
                }

                arg
            });

            quote! {
                #( #attrs )*
                #ident { #( #args ),* },
            }
        });

        let vis = &self.vis;
        let ident = &self.request_ident;
        let generics = self.request_generics.as_ref();

        quote! {
            #[allow(missing_docs)]
            #[derive(Debug)]
            #[derive(::reverie_rpc::serde::Serialize, ::reverie_rpc::serde::Deserialize)]
            #[serde(crate = "reverie_rpc::serde")]
            #vis enum #ident #generics {
                #( #variants )*
            }
        }
    }

    /// Expands the associated response type for each method's return type.
    fn expand_response_enum(&self) -> TokenStream {
        let variants = self.methods.iter().filter_map(|method| {
            if method.method_attrs.no_response {
                // Don't expand this variant if it's a send-only method.
                return None;
            }

            let attrs = &method.attrs;
            let ident = &method.camel_ident;

            let output = match &method.output {
                syn::ReturnType::Default => quote!(()),
                syn::ReturnType::Type(_, ret) => quote!(#ret),
            };

            Some(quote! {
                #( #attrs )*
                #ident(#output),
            })
        });

        let vis = &self.vis;
        let ident = &self.response_ident;

        quote! {
            #[allow(missing_docs)]
            #[derive(Debug)]
            #[derive(::reverie_rpc::serde::Serialize, ::reverie_rpc::serde::Deserialize)]
            #[serde(crate = "reverie_rpc::serde")]
            #vis enum #ident {
                #( #variants )*
            }
        }
    }

    fn expand_client(&self) -> TokenStream {
        let vis = &self.vis;
        let attrs = &self.attrs;
        let client_ident = &self.client_ident;
        let request = &self.request_ident;
        let response = &self.response_ident;

        let req_generics: Option<syn::Generics> = self.request_generics.as_ref().map(|_| {
            // HACK: The lifetime parameter for the request type shouldn't need
            // to force the service client type to also have a lifetime
            // parameter because the request itself isn't stored in the service
            // client, it's just sent through the channel.
            //
            // However, we need the channel to have these parameters so that
            // `MakeClient` knows the type of the request/response. Thus, in
            // order to ensure we aren't leaking the request type's lifetime
            // parameter into the service client's generic parameters and
            // complicating it's usage, we say that the request type has a
            // static lifetime and transmute it just before sending it through
            // the channel. This is terrible, but perfectly safe because we
            // don't store the request before serializing it. Generic Associated
            // Types (GATs) might help with this, but they don't support dyn
            // traits which is useful for enabling nesting of channels (and thus
            // composition of global state).
            syn::parse_quote!(<'static>)
        });

        let methods = self.methods.iter().map(|method| {
            let attrs = &method.attrs;
            let ident = &method.ident;
            let camel_ident = &method.camel_ident;
            let args = &method.args;
            let arg_pats = method.args.iter().map(|pat_type| &pat_type.pat);
            let output = &method.output;

            if method.method_attrs.no_response {
                quote! {
                    #( #attrs )*
                    pub fn #ident(&self, #( #args ),*) {
                        use ::reverie_rpc::Channel;

                        // Transmute is safe because the channel doesn't store
                        // the request type.
                        let request: #request #req_generics = unsafe {
                            ::core::mem::transmute(#request::#camel_ident { #( #arg_pats ),* })
                        };

                        self.channel.send(&request);
                    }
                }
            } else {
                quote! {
                    #( #attrs )*
                    pub fn #ident(&self, #( #args ),*) #output {
                        use ::reverie_rpc::Channel;

                        // Transmute is safe because the channel doesn't store
                        // the request type.
                        let request: #request #req_generics = unsafe {
                            ::core::mem::transmute(#request::#camel_ident { #( #arg_pats ),* })
                        };

                        match self.channel.call(&request) {
                            #response::#camel_ident(ret) => ret,
                            other => panic!("Got unexpected response: {:?}", other),
                        }
                    }
                }
            }
        });

        quote! {
            #( #attrs )*
            #vis struct #client_ident {
                channel: ::reverie_rpc::BoxChannel<#request #req_generics, #response>,
            }

            impl ::reverie_rpc::MakeClient for #client_ident {
                type Request = #request #req_generics;
                type Response = #response;

                fn make_client(channel: ::reverie_rpc::BoxChannel<Self::Request, Self::Response>) -> Self {
                    Self {
                        channel,
                    }
                }
            }

            impl #client_ident {
                #( #methods )*
            }
        }
    }
}

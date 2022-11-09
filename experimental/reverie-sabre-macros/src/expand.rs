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

use crate::Tool;

impl ToTokens for Tool {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let mut item_impl = self.outer_item.clone();

        let ty = &item_impl.self_ty;
        // Implement ToolGlobal so that we can access it from any of the
        // callbacks specified by sbr_init.
        tokens.extend(quote! {
            impl ::reverie_sabre::ToolGlobal for #ty {
                type Target = #ty;

                fn global() -> &'static Self::Target {
                    use ::reverie_sabre::internal::OnceCell;
                    static __TOOL_INSTANCE: OnceCell<#ty> = OnceCell::new();
                    __TOOL_INSTANCE.get_or_init(::reverie_sabre::internal::init_tool)
                }
            }
        });

        let mut fn_icept_structs = quote! {};

        let mut type_impl = quote! {};
        // Traversing "detoured" methods declarations and preparing the plumbing
        // to hook up to sabre we need a callback, a field to hold a pointer to
        // original function, a stub pointer, DETOURS strucure, etc
        for method in &self.detoured_methods {
            let field_ident = &method.undetoured_field_name;
            let callback_ident = &method.callback_name;
            let stub_ident = &method.stub_name;
            let undetoured_method_name = &method.undetoured_method_name;
            let args = &method.outer_item.sig.inputs;
            let arg_pats = args
                .iter()
                .filter_map(|pat_type| match pat_type {
                    syn::FnArg::Typed(pat) => Some(&pat.pat),
                    _ => None,
                })
                .collect::<Vec<_>>();
            let output = &method.outer_item.sig.output;
            let function_type_name = &method.detoured_function_type_name;
            let original_marked_method = &method.outer_item;
            let detoured_definition_name = &method.detoured_definition_name;

            let lib_name_c_str = syn::LitStr::new(
                format!("{0}\0", method.attrs.lib).as_str(),
                proc_macro2::Span::call_site(),
            );

            let func_name_c_str = syn::LitStr::new(
                format!("{0}\0", method.attrs.func).as_str(),
                proc_macro2::Span::call_site(),
            );

            fn_icept_structs.extend(quote! {
                sabre::ffi::fn_icept {
                    lib_name: #lib_name_c_str.as_ptr() as *const i8,
                    fn_name: #func_name_c_str.as_ptr() as *const i8,
                    icept_callback: #callback_ident,
                },
            });

            type_impl.extend(quote! {
                fn #undetoured_method_name(#args) #output  {
                    unsafe {
                        if let Some(f) = #field_ident {
                            return f(#(#arg_pats),*);
                        }
                        panic!("original function wasn't captured");
                    }
                }

                #original_marked_method
            });

            tokens.extend(quote! {
                type #function_type_name = fn(#args) #output;
                static mut #field_ident: Option<#function_type_name> = None;

                unsafe extern "C" fn #stub_ident(#args) #output  {
                    #ty::#detoured_definition_name(#(#arg_pats),*)
                }

                extern "C" fn #callback_ident(func: sabre::ffi::void_void_fn) -> sabre::ffi::void_void_fn {
                    unsafe {
                        #field_ident = Some(std::mem::transmute(func));
                        std::mem::transmute(#stub_ident as *const())
                    }
                }
            });
        }

        tokens.extend(quote! {
            impl #ty {
               #type_impl
            }
        });

        item_impl.items.push(syn::ImplItem::Method(
            syn::parse2(quote! {
                fn detours() -> &'static [sabre::ffi::fn_icept] {
                    static DETOURS: &[sabre::ffi::fn_icept] = &[
                        #fn_icept_structs
                    ];
                    DETOURS
                }
            })
            .unwrap(),
        ));

        // Expand the original `impl Tool for MyTool` block.
        item_impl.to_tokens(tokens);

        // Implement the entry point for our plugin.
        tokens.extend(quote! {
            #[no_mangle]
            pub extern "C" fn sbr_init(
                argc: *mut i32,
                argv: *mut *mut *mut libc::c_char,
                fn_icept_reg: sabre::ffi::icept_reg_fn,
                vdso_callback: *mut Option<sabre::ffi::handle_vdso_fn>,
                syscall_handler: *mut Option<sabre::ffi::handle_syscall_fn>,
                rdtsc_handler: *mut Option<sabre::ffi::handle_rdtsc_fn>,
                post_load: *mut Option<sabre::ffi::post_load_fn>,
                sabre_path: *const libc::c_char,
                plugin_path: *const libc::c_char,
            ) {
                ::reverie_sabre::internal::sbr_init::<#ty>(
                    argc,
                    argv,
                    fn_icept_reg,
                    vdso_callback,
                    syscall_handler,
                    rdtsc_handler,
                    post_load,
                    sabre_path,
                    plugin_path,
                )
            }
        });
    }
}

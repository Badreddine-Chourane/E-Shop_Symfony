<?php
namespace App\Controller;

use App\Entity\Categories;
use App\Repository\ProductsRepository;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use App\Repository\CategoriesRepository;

class CategoriesController extends AbstractController
{
    // Show categories list (root route for categories)
    #[Route('/categories', name: 'categories_index')]
    public function index(CategoriesRepository $categoriesRepository): Response
    {
        return $this->render('categories/categories.html.twig', [
            'categories' => $categoriesRepository->findBy([], ['categoryOrder' => 'asc'])
        ]);
    }

    // Show products in a specific category
    #[Route('/categories/{slug}', name: 'categories_list')]
    public function list(Categories $category, ProductsRepository $productsRepository, Request $request): Response
    {
        // Get page number from URL query string, default is 1
        $page = $request->query->getInt('page', 1);

        // Get paginated list of products for the selected category
        $products = $productsRepository->findProductsPaginated($page, $category->getSlug(), 4);

        return $this->render('categories/list.html.twig', compact('category', 'products'));
    }
}
